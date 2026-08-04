use maya_libafl_poc::{catalogue, config, fsm, generator, input, executor, feedback};

use std::{
    borrow::Cow,
    fs::OpenOptions,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use generator::{CatalogueGenerator, StatefulGenerator};
use input::{CcsdsSequenceInput, SelectedMutator, ChainMutator, FixedFieldsMutator};
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

/// Retire les variables d'environnement injectées par VSCode (installé en
/// snap) qui redirigent GTK_PATH/GIO_MODULE_DIR/LOCPATH/etc. vers ses propres
/// libs bundlées. `make launch` invoque gnome-terminal en interne (une
/// fenêtre par conteneur, dont nos-fsw) ; avec ces variables héritées,
/// gnome-terminal.real plante avant même d'ouvrir une fenêtre (symbol lookup
/// error, conflit de version glibc) — make launch tourne alors sans qu'aucune
/// fenêtre n'apparaisse. Même correctif que _clean_env_for_gui() côté
/// wrapper.py (qui gère le cas crash cFS ; ceci gère le cas Ctrl+C).
fn clean_env_for_gui(cmd: &mut Command) {
    for key in [
        "GTK_PATH", "GTK_EXE_PREFIX", "GIO_MODULE_DIR",
        "GDK_PIXBUF_MODULE_FILE", "GDK_PIXBUF_MODULEDIR",
        "GTK_IM_MODULE_FILE", "LOCPATH", "GSETTINGS_SCHEMA_DIR",
        "LD_LIBRARY_PATH",
    ] {
        cmd.env_remove(key);
    }
    for (key, _) in std::env::vars() {
        if key.starts_with("SNAP") {
            cmd.env_remove(key);
        }
    }
}

/// Chemin du log où atterrit la sortie (très verbeuse) de make stop/launch,
/// au lieu de spammer le terminal de cargo run à chaque redémarrage.
const NOS3_RESTART_LOG: &str = "/tmp/nos3_restart.log";

/// Arrête NOS3 (make stop) sans le relancer — utilisé sur double Ctrl+C, où
/// l'utilisateur veut un arrêt total (fuzzer + NOS3), pas juste la fin de la
/// boucle Rust en laissant les conteneurs Docker tourner.
fn stop_nos3() {
    eprintln!("[main] arrêt de NOS3 (make stop)... (détails : {NOS3_RESTART_LOG})");
    let log_out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(NOS3_RESTART_LOG)
        .expect("impossible d'ouvrir le log de redémarrage NOS3");
    let log_err = log_out.try_clone().expect("clone du handle de log");

    let mut cmd = Command::new("make");
    cmd.arg("stop")
        .current_dir(NOS3_DIR)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));
    let _ = cmd.status();
    eprintln!("[main] NOS3 arrêté.");
}

/// Redémarre NOS3 proprement (make stop && make launch) pour repartir d'un
/// état initial connu, puis bloque jusqu'à ce que cFS réponde de nouveau.
/// Équivalent Rust de _wait_for_nos3_ready() dans wrapper.py, utilisé ici
/// quand on tue nous-mêmes la séquence en cours (Ctrl+C), donc wrapper.py
/// n'a pas l'occasion de le faire lui-même.
fn restart_nos3() {
    eprintln!(
        "[main] redémarrage NOS3 (make stop - make launch)... (détails : {NOS3_RESTART_LOG})"
    );

    // make stop reste bloquant et sans fenêtre : on doit attendre la fin du
    // nettoyage avant de relancer.
    {
        let log_out = OpenOptions::new()
            .create(true)
            .append(true)
            .open(NOS3_RESTART_LOG)
            .expect("impossible d'ouvrir le log de redémarrage NOS3");
        let log_err = log_out.try_clone().expect("clone du handle de log");

        let mut cmd = Command::new("make");
        cmd.arg("stop")
            .current_dir(NOS3_DIR)
            .stdout(Stdio::from(log_out))
            .stderr(Stdio::from(log_err));
        let _ = cmd.status();
    }

    // make launch enveloppé dans gnome-terminal, comme le fait déjà
    // _wait_for_nos3_ready() côté wrapper.py (chemin crash cFS) — sans ça, les
    // --tab émis à l'intérieur de launch.sh n'atterrissent pas dans la même
    // fenêtre quand le process appelant (nous) n'est pas lui-même déjà
    // rattaché à un terminal ouvert par gnome-terminal (vérifié : en env
    // identique, `make launch` direct depuis un terminal groupe bien les
    // onglets, mais depuis ce binaire Rust ça ouvrait une fenêtre par onglet).
    {
        let mut cmd = Command::new("gnome-terminal");
        cmd.arg(format!("--working-directory={NOS3_DIR}"))
            .arg("--")
            .arg("make")
            .arg("launch");
        clean_env_for_gui(&mut cmd);
        let _ = cmd.status();
    }

    eprintln!("[main] make launch lancé : attente cFS (max {}s)...", RESTART_WAIT.as_secs());
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

    // --fixed-fields <path> (optionnel) : post-processing appliqué après
    // chaque mutation automatique. Absent → aucun override (fuzzing 100%
    // automatique). Pour l'activer : cargo run -- --fixed-fields fixed_fields.toml
    let cli_args: Vec<String> = std::env::args().collect();
    let fixed_fields_path = cli_args.iter()
        .position(|a| a == "--fixed-fields")
        .and_then(|i| cli_args.get(i + 1))
        .cloned();
    let fixed_fields = match &fixed_fields_path {
        Some(path) => {
            let fields = config::load_fixed_fields(path);
            eprintln!("[main] --fixed-fields {path} : {} champ(s) figé(s) actif(s)", fields.len());
            fields
        }
        None => Vec::new(),
    };

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
                // Annule tout cancel_flag laissé par le 1er Ctrl+C (celui qui
                // vient de déclencher ce double-appui) — sinon la boucle
                // principale l'honore encore et redémarre NOS3 avant de
                // s'arrêter (voir ordre des checks après fuzz_one()).
                cancel_flag.store(false, Ordering::SeqCst);
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
        config::FuzzMode::All => {
            let mut gen = CatalogueGenerator::new(cat).with_all_ordered();
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
    let selected_mutator     = SelectedMutator::new(cfg.mutators.clone());
    let fixed_fields_mutator = FixedFieldsMutator::new(fixed_fields);
    let combined_mutator     = ChainMutator::new(selected_mutator, fixed_fields_mutator);
    // max_iterations=1 (au lieu du défaut LibAFL, un lot aléatoire jusqu'à 128
    // exécutions par fuzz_one()) : sans ça, un Ctrl+C peut rester sans effet
    // visible pendant tout un lot avant que la boucle ne revienne vérifier
    // cancel_flag/stop_flag — avec 1, chaque exécution individuelle rend la
    // main immédiatement après.
    let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
        combined_mutator,
        std::num::NonZeroUsize::new(1).unwrap()
    ));

    // Boucle manuelle (au lieu de fuzzer.fuzz_loop) pour pouvoir réagir au
    // Ctrl+C : annuler juste la séquence en cours et continuer, ou arrêter
    // proprement sur double Ctrl+C.
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            println!("[main] Arrêt total (Ctrl+C x2).");
            stop_nos3();
            break;
        }

        if let Err(e) = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            eprintln!("[main] Erreur pendant l'itération (probablement due à l'annulation): {e}");
        }

        // stop_flag est prioritaire sur cancel_flag : un double Ctrl+C pendant
        // que fuzz_one() était bloqué peut laisser cancel_flag à true (mis par
        // le 1er appui) EN MÊME TEMPS que stop_flag (mis par le 2e) — sans ce
        // check en premier, on redémarrerait NOS3 pour rien juste avant de
        // s'arrêter au tour de boucle suivant.
        if stop_flag.load(Ordering::SeqCst) {
            continue;
        }

        if cancel_flag.swap(false, Ordering::SeqCst) {
            println!("[main] Séquence annulée — redémarrage NOS3 avant de continuer...");
            restart_nos3();
        }
    }
}
