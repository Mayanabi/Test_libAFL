mod catalogue;
mod config;
mod fsm;
mod generator;
mod input;
mod executor;
mod feedback;

use std::{
    borrow::Cow,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use generator::{CatalogueGenerator, StatefulGenerator};
use input::{CcsdsSequenceInput, SelectedMutator};
use executor::Nos3Executor;
use feedback::Nos3Feedback;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::command::CommandConfigurator,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::SimpleMonitor,
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

// Répertoire du repo NOS3 (contient le Makefile : make stop / make launch) —
// même chemin que _NOS3_DIR côté wrapper.py.
const NOS3_DIR: &str = "/home/jstar/Desktop/github-nos3";
// Temps max d'attente que cFS réponde après make launch.
const RESTART_WAIT: Duration = Duration::from_secs(90);
const RESTART_POLL: Duration = Duration::from_secs(2);
// Fenêtre pendant laquelle un second Ctrl+C est considéré comme un "double
// Ctrl+C" (arrêt total) plutôt qu'une nouvelle annulation.
const DOUBLE_CTRLC_WINDOW: Duration = Duration::from_secs(2);

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

/// Variante non-panicking de resolve_cfs_pid(), pour le polling pendant un
/// redémarrage — cFS n'est pas censé répondre tout de suite après make launch.
fn try_resolve_cfs_pid() -> Option<String> {
    let out = std::process::Command::new("python3")
        .args([
            "-c",
            "import sys; sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev'); \
             from ProcessMonitoring import get_cfs_pid; print(get_cfs_pid() or '', end='')",
        ])
        .output()
        .ok()?;
    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if result.is_empty() { None } else { Some(result) }
}

/// Tue une commande en cours (la séquence en train d'être envoyée à NOS3).
fn kill_pid(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).status();
    }
}

/// Redémarre NOS3 proprement (make stop && make launch) pour repartir d'un
/// état initial connu, puis bloque jusqu'à ce que cFS réponde de nouveau.
/// Équivalent Rust de _wait_for_nos3_ready() dans wrapper.py, utilisé ici
/// quand on tue nous-mêmes la séquence en cours (Ctrl+C), donc wrapper.py
/// n'a pas l'occasion de le faire lui-même.
fn restart_nos3() {
    eprintln!("[main] redémarrage NOS3 (make stop - make launch)...");
    for target in ["stop", "launch"] {
        let _ = Command::new("make").arg(target).current_dir(NOS3_DIR).status();
    }

    eprintln!("[main] make launch terminé : attente cFS (max {}s)...", RESTART_WAIT.as_secs());
    let deadline = Instant::now() + RESTART_WAIT;
    while Instant::now() < deadline {
        if let Some(pid) = try_resolve_cfs_pid() {
            eprintln!("[main] NOS3 de nouveau disponible (PID={pid}), attente init...");
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        std::thread::sleep(RESTART_POLL);
    }
    eprintln!("[main] NOS3 toujours absent après {}s", RESTART_WAIT.as_secs());
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

    // ── Ctrl+C : annulation de séquence (simple) / arrêt total (double) ──────
    // Un seul Ctrl+C tue la séquence en cours (débloque l'attente de LibAFL sur
    // le child wrapper.py), redémarre NOS3, puis le fuzzing continue avec la
    // séquence suivante. Deux Ctrl+C rapprochés (< DOUBLE_CTRLC_WINDOW) arrêtent
    // tout proprement à la fin de l'itération en cours.
    let current_pid   = Arc::new(Mutex::new(None::<u32>));
    let cancel_flag   = Arc::new(AtomicBool::new(false));
    let stop_flag     = Arc::new(AtomicBool::new(false));
    // Consommé par Nos3Feedback pour ne jamais ajouter au corpus le résultat
    // d'une séquence qu'on vient de tuer nous-mêmes (stdout garbage/incomplet).
    let killed_flag   = Arc::new(AtomicBool::new(false));
    let last_ctrlc: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    {
        let current_pid = current_pid.clone();
        let cancel_flag = cancel_flag.clone();
        let stop_flag   = stop_flag.clone();
        let killed_flag = killed_flag.clone();
        let last_ctrlc  = last_ctrlc.clone();
        ctrlc::set_handler(move || {
            let now = Instant::now();
            let mut last = last_ctrlc.lock().unwrap();
            let is_double = last.is_some_and(|t| now.duration_since(t) < DOUBLE_CTRLC_WINDOW);
            *last = Some(now);

            if let Some(pid) = current_pid.lock().unwrap().take() {
                kill_pid(pid);
                killed_flag.store(true, Ordering::SeqCst);
            }

            if is_double {
                eprintln!("[main] Ctrl+C x2 : arrêt total demandé.");
                stop_flag.store(true, Ordering::SeqCst);
            } else {
                eprintln!("[main] Ctrl+C : annulation de la séquence en cours.");
                cancel_flag.store(true, Ordering::SeqCst);
            }
        })
        .expect("Impossible d'installer le handler Ctrl+C");
    }

    let nos3_executor = Nos3Executor::new(
        "wrapper.py",
        Duration::from_secs(120),
        stdout_handle.clone(),
        nos3_ip,
        cfs_pid,
        fuzz_mode_str,
        current_pid,
    );

    // ── Feedback ──────────────────────────────────────────────────────────────
    let mut objective = CrashFeedback::new();

    // En mode stateful, le feedback partage la FSM avec le générateur.
    let (shared_fsm, mut feedback) = if cfg.mode == config::FuzzMode::Stateful {
        let fsm = fsm::load_shared(&cfg.fsm_dir);
        let fb  = Nos3Feedback::new_with_fsm(stdout_handle.clone(), fsm.clone(), killed_flag.clone());
        (Some(fsm), fb)
    } else {
        (None, Nos3Feedback::new(stdout_handle.clone(), killed_flag.clone()))
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
    // Choisis via `mutators` dans fuzz_config.toml : un seul → toujours celui-là ;
    // plusieurs → un tiré au hasard à chaque paquet muté (voir SelectedMutator).
    let selected_mutator = SelectedMutator::new(cfg.mutators.clone());
    let mut stages = tuple_list!(StdMutationalStage::new(selected_mutator));

    // Boucle manuelle (au lieu de fuzzer.fuzz_loop) pour pouvoir réagir au
    // Ctrl+C : annuler juste la séquence en cours et continuer, ou arrêter
    // proprement sur double Ctrl+C.
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            println!("[main] Arrêt total (Ctrl+C x2).");
            break;
        }

        if let Err(e) = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            eprintln!("[main] Erreur pendant l'itération (probablement due à l'annulation): {e}");
        }

        if cancel_flag.swap(false, Ordering::SeqCst) {
            println!("[main] Séquence annulée — redémarrage NOS3 avant de continuer...");
            restart_nos3();
        }
    }
}
