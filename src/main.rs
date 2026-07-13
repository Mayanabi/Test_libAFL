mod catalogue;
mod config;
mod fsm;
mod generator;
mod input;
mod executor;
mod feedback;

use std::{borrow::Cow, path::PathBuf, time::Duration};

use generator::{CatalogueGenerator, StatefulGenerator};
use input::{
    ArgValueMutator, CcsdsSequenceInput,
    CommandReorderMutator, DelayMutator,
    FcWalkMutator, FloatSpecialMutator, IntBoundaryMutator,
};
use executor::Nos3Executor;
use feedback::Nos3Feedback;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::command::CommandConfigurator,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::SimpleMonitor,
    mutators::scheduled::HavocScheduledMutator,
    observers::StdOutObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::{tuple_list, Handled},
};

fn python_oneliner(code: &str, label: &str) -> String {
    let out = std::process::Command::new("python3")
        .args(["-c", code])
        .output()
        .unwrap_or_else(|e| panic!("Impossible de lancer python3 pour {label}: {e}"));
    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if result.is_empty() {
        panic!(
            "{label} introuvable — NOS3 est-il lancé ?\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    result
}

fn resolve_nos3_ip() -> String {
    python_oneliner(
        "import sys; sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev'); \
         from CmdSender import getDockerIP; print(getDockerIP(), end='')",
        "IP NOS3",
    )
}

fn resolve_cfs_pid() -> String {
    python_oneliner(
        "import sys; sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev'); \
         from ProcessMonitoring import get_cfs_pid; print(get_cfs_pid() or '', end='')",
        "PID cFS",
    )
}

pub fn main() {
    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = config::load("fuzz_config.toml");

    let fuzz_mode_str = match cfg.mode {
        config::FuzzMode::Naive    => "naive",
        config::FuzzMode::Stateful => "stateful",
        _                          => "normal",
    };

    // ── Résolution IP / PID (une seule fois) ─────────────────────────────────
    let nos3_ip = resolve_nos3_ip();
    let cfs_pid = resolve_cfs_pid();

    // ── Observer + Executor ───────────────────────────────────────────────────
    let stdout_observer = StdOutObserver::new_piped(Cow::Borrowed("stdout"))
        .expect("Failed to create stdout observer");
    let stdout_handle = stdout_observer.handle();

    let nos3_executor = Nos3Executor::new(
        "wrapper.py",
        Duration::from_secs(120),
        stdout_handle.clone(),
        nos3_ip,
        cfs_pid,
        fuzz_mode_str,
    );

    // ── Feedback ──────────────────────────────────────────────────────────────
    let mut objective = CrashFeedback::new();

    // En mode stateful, le feedback partage la FSM avec le générateur.
    let (shared_fsm, mut feedback) = if cfg.mode == config::FuzzMode::Stateful {
        let fsm = fsm::load_shared(&cfg.fsm_dir);
        let fb  = Nos3Feedback::new_with_fsm(stdout_handle.clone(), fsm.clone());
        (Some(fsm), fb)
    } else {
        (None, Nos3Feedback::new(stdout_handle.clone()))
    };

    // ── State, manager, fuzzer ────────────────────────────────────────────────
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<CcsdsSequenceInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon         = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr     = SimpleEventManager::new(mon);
    let scheduler   = QueueScheduler::new();
    let mut fuzzer  = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = nos3_executor.into_executor(
        tuple_list!(stdout_observer),
        Some(stdout_handle),
        None,
    );

    // ── Catalogue ─────────────────────────────────────────────────────────────
    let raw_cat = catalogue::load("catalogue_dump.json");
    let cat     = catalogue::filter(raw_cat, &cfg);

    if cat.is_empty() {
        panic!(
            "Le catalogue filtré est vide — vérifie fuzz_config.toml\n\
             (apps={:?}, fuzz_priority={:?})",
            cfg.apps, cfg.fuzz_priority
        );
    }

    // ── Génération des seeds initiales selon le mode ──────────────────────────
    match cfg.mode {
        config::FuzzMode::Stateful => {
            let fsm = shared_fsm.expect("FSM should be loaded for stateful mode");
            let mut gen = StatefulGenerator::new(cat, fsm);
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, cfg.seed_count)
                .expect("Failed to generate initial corpus");
        }
        config::FuzzMode::Naive => {
            let mut gen = CatalogueGenerator::new(cat)
                .with_naive_batch(cfg.naive_batch_size);
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, cfg.seed_count)
                .expect("Failed to generate initial corpus");
        }
        config::FuzzMode::CrossApp => {
            let mut gen = CatalogueGenerator::new(cat)
                .with_cross_app(cfg.cross_app_min_tc, cfg.cross_app_max_tc);
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, cfg.seed_count)
                .expect("Failed to generate initial corpus");
        }
        _ => {
            let mut gen = CatalogueGenerator::new(cat);
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, cfg.seed_count)
                .expect("Failed to generate initial corpus");
        }
    }

    // ── Mutateurs ─────────────────────────────────────────────────────────────
    let mutators = tuple_list!(
        FcWalkMutator,
        IntBoundaryMutator,
        FloatSpecialMutator,
        CommandReorderMutator,
        ArgValueMutator,
        DelayMutator,
    );

    let mutator_scheduler = HavocScheduledMutator::new(mutators);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator_scheduler));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
