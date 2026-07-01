mod catalogue;
mod config;
mod generator;
mod input;
mod executor;
mod feedback;

use std::{borrow::Cow, path::PathBuf, time::Duration};

use generator::CatalogueGenerator;
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

/// Lance un one-liner Python et retourne sa sortie stdout (trimmed).
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

/// Récupère le PID initial de core-cpu1 une seule fois.
/// Évite 2 appels `docker exec` par exécution dans wrapper.py (50–500ms chacun).
fn resolve_cfs_pid() -> String {
    python_oneliner(
        "import sys; sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev'); \
         from ProcessMonitoring import get_cfs_pid; print(get_cfs_pid() or '', end='')",
        "PID cFS",
    )
}

pub fn main() {
    // Résolus une seule fois — évitent 2 × docker exec par exécution dans wrapper.py
    let nos3_ip  = resolve_nos3_ip();
    let cfs_pid  = resolve_cfs_pid();

    // --- Observer stdout : capture le verdict JSON imprimé par wrapper.py ---
    let stdout_observer = StdOutObserver::new_piped(Cow::Borrowed("stdout"))
        .expect("Failed to create stdout observer");
    let stdout_handle = stdout_observer.handle();

    // --- Executor réel vers NOS3 (wrapper Python + subprocess) ---
    let nos3_executor = Nos3Executor::new(
        "wrapper.py",
        Duration::from_secs(120), // > _RESTART_WAIT (90s) pour laisser wrapper.py attendre NOS3
        stdout_handle.clone(),
        nos3_ip,
        cfs_pid,
    );

    // --- Feedback : "intéressant" = verdict NOS3 jamais vu auparavant ---
    // CrashFeedback est le critère secondaire (objective) : retour non-zéro du wrapper.
    let mut objective = CrashFeedback::new();
    let mut feedback  = Nos3Feedback::new(stdout_handle.clone());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<CcsdsSequenceInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon      = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr  = SimpleEventManager::new(mon);
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = nos3_executor.into_executor(
        tuple_list!(stdout_observer),
        Some(stdout_handle),
        None,
    );

    // --- Config de campagne : fuzz_config.toml ---
    let cfg = config::load("fuzz_config.toml");

    // --- Catalogue NOS3 filtré selon la config ---
    // catalogue_dump.json produit par : python3 dump_catalogue.py
    let raw_cat = catalogue::load("catalogue_dump.json");
    let cat     = catalogue::filter(raw_cat, &cfg);

    if cat.is_empty() {
        panic!(
            "Le catalogue filtré est vide — vérifie fuzz_config.toml\n\
             (apps={:?}, fuzz_priority={:?})",
            cfg.apps, cfg.fuzz_priority
        );
    }
    let base_gen = CatalogueGenerator::new(cat);
    let mut generator = if cfg.mode == config::FuzzMode::CrossApp {
        base_gen.with_cross_app(cfg.cross_app_min_tc, cfg.cross_app_max_tc)
    } else {
        base_gen
    };
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, cfg.seed_count)
        .expect("Failed to generate the initial corpus");

    // --- Mutateurs ---
    // Ordonnés du plus sémantique au plus aléatoire.
    // HavocScheduledMutator en choisit plusieurs par exécution aléatoirement.
    let mutators = tuple_list!(
        FcWalkMutator,          // FC ±1..16 ou aléatoire → nouveau handler cFS
        IntBoundaryMutator,     // 0 / max / max/2 / frontières signed pour UINT/INT
        FloatSpecialMutator,    // NaN / Inf / 0.0 / max pour FLOAT
        CommandReorderMutator,  // swap deux commandes → teste l'ordre (cross_app)
        ArgValueMutator,        // havoc byte-level pour STRING/BLOCK et chaos général
        DelayMutator,           // explore l'impact des délais inter-commandes
    );

    let mutator_scheduler = HavocScheduledMutator::new(mutators);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator_scheduler));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
