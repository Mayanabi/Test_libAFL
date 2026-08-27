use maya_libafl_poc::{catalogue, config, fsm, generator, input, executor, feedback, nos3_control, state_catalogue};

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
use input::{CcsdsSequenceInput, SelectedMutator, ChainMutator, FixedFieldsMutator};
use executor::Nos3Executor;
use feedback::Nos3Feedback;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::command::CommandConfigurator,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::SimpleMonitor,
    observers::StdOutObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasSolutions, StdState},
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::{tuple_list, Handled},
};

// Fenêtre pendant laquelle un second Ctrl+C est considéré comme un "double
// Ctrl+C" (arrêt total) plutôt qu'une nouvelle annulation. Après le 1er
// Ctrl+C, la boucle principale attend cette même durée avant de committer au
// redémarrage NOS3 — le temps de voir si un 2e Ctrl+C arrive (voir la boucle
// principale : le redémarrage est retardé, pas juste la classification).
const DOUBLE_CTRLC_WINDOW: Duration = Duration::from_secs(3);

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

    // --list-components : affiche les composants du catalogue d'état
    // (state_sequences/) et quitte, sans toucher à NOS3.
    if cli_args.iter().any(|a| a == "--list-components") {
        state_catalogue::list_components();
        return;
    }

    // --component <NOM> (optionnel) : part de la séquence d'état connue
    // state_sequences/<NOM>.json (voir state_catalogue.rs) au lieu de la
    // génération procédurale depuis catalogue_dump.json — pour un composant
    // qui a une machine d'état de commandes (ex: NOVATEL_OEM615 : NOOP →
    // ENABLE → LOG → UNLOG → RST_COUNTERS → DISABLE). --start-step N force
    // fuzz=false avant l'étape N et fuzz=true à partir de N (override le
    // fuzz du fichier), pour ne muter qu'à partir d'un état déjà atteint.
    // --show affiche la séquence chargée et quitte, sans lancer le fuzzing.
    let component_seed = cli_args.iter()
        .position(|a| a == "--component")
        .and_then(|i| cli_args.get(i + 1))
        .map(|name| {
            let mut seed = state_catalogue::load_component(name);
            if let Some(n) = cli_args.iter()
                .position(|a| a == "--start-step")
                .and_then(|i| cli_args.get(i + 1))
            {
                let n: i32 = n.parse().unwrap_or_else(|e| panic!("--start-step invalide '{n}': {e}"));
                state_catalogue::apply_start_step(&mut seed, n);
            }
            eprintln!(
                "[main] --component {name} : séquence catalogue ({} étape(s)) utilisée comme seed",
                seed.commands.len()
            );
            seed
        });

    if cli_args.iter().any(|a| a == "--show") {
        match &component_seed {
            Some(seed) => state_catalogue::print_sequence_preview(seed),
            None => eprintln!("[main] --show sans --component : rien à afficher."),
        }
        return;
    }

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

    // ── Génération des seeds initiales ────────────────────────────────────────
    // --component (voir plus haut) prend le pas sur `mode` : la séquence du
    // catalogue d'état sert de seed directement, la génération procédurale
    // depuis catalogue_dump.json n'a pas lieu d'être dans ce cas.
    //
    // generate_initial_inputs(..., 1) : une seule seed initiale, mutée ensuite
    // à l'infini par la boucle principale — plusieurs seeds n'apportaient pas
    // de diversité utile ici (identiques pour --component, et de toute façon
    // remplacées par le corpus qui grossit au fil du fuzzing pour les autres
    // modes).
    if let Some(seed) = component_seed {
        let mut gen = generator::FixedSeedGenerator::new(seed);
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
            .expect("Failed to generate initial corpus");
    } else {
        // ── Catalogue ─────────────────────────────────────────────────────────
        let raw_cat = catalogue::load("catalogue_dump.json");
        let cat     = catalogue::filter(raw_cat, &cfg);

        if cat.is_empty() {
            panic!(
                "Le catalogue filtré est vide — vérifie fuzz_config.toml\n\
                 (apps={:?})",
                cfg.apps
            );
        }

        match cfg.mode {
            config::FuzzMode::Stateful => {
                let fsm = shared_fsm.expect("FSM should be loaded for stateful mode");
                let mut gen = StatefulGenerator::new(cat, fsm);
                state
                    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
                    .expect("Failed to generate initial corpus");
            }
            config::FuzzMode::Naive => {
                let mut gen = CatalogueGenerator::new(cat)
                    .with_naive_batch(cfg.naive_batch_size);
                state
                    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
                    .expect("Failed to generate initial corpus");
            }
            config::FuzzMode::CrossApp => {
                let mut gen = CatalogueGenerator::new(cat)
                    .with_cross_app(cfg.cross_app_min_tc, cfg.cross_app_max_tc);
                state
                    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
                    .expect("Failed to generate initial corpus");
            }
            config::FuzzMode::All => {
                let mut gen = CatalogueGenerator::new(cat).with_all_ordered();
                state
                    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
                    .expect("Failed to generate initial corpus");
            }
            _ => {
                let mut gen = CatalogueGenerator::new(cat);
                state
                    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 1)
                    .expect("Failed to generate initial corpus");
            }
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
    //
    // solutions_count : nombre de crashes déjà dans ./crashes/ (chargés au
    // démarrage de StdState si le dossier existait déjà) — sert de référence
    // pour détecter un NOUVEAU crash pendant cette session (voir plus bas).
    let solutions_count = state.solutions().count();
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            println!("[main] Arrêt total (Ctrl+C x2).");
            nos3_control::stop_nos3();
            break;
        }

        if let Err(e) = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            eprintln!("[main] Erreur pendant l'itération (probablement due à l'annulation): {e}");
        }

        // Le redémarrage automatique de NOS3 sur crash est désactivé côté
        // wrapper.py (_wait_for_nos3_ready commentée) — donc un cFS mort le
        // reste pour de vrai après un crash. Sans ce check, la boucle
        // continuerait indéfiniment à générer et envoyer des séquences dans
        // le vide. On arrête plutôt tout net, sans toucher à NOS3, pour
        // laisser l'état crashé intact et inspectable.
        if state.solutions().count() > solutions_count {
            println!(
                "[main] Crash cFS confirmé — arrêt du fuzzing (pas de redémarrage \
                 automatique, voir wrapper.py). NOS3 est laissé tel quel pour inspection ; \
                 relance-le toi-même (`make launch` dans {}) puis relance `cargo run`.",
                nos3_control::NOS3_DIR
            );
            break;
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
            // On ne committe pas tout de suite au redémarrage : on attend
            // DOUBLE_CTRLC_WINDOW pour laisser le temps à un 2e Ctrl+C
            // d'arriver et de transformer ça en arrêt total. Sans cette
            // pause, le redémarrage démarrait immédiatement après le 1er
            // Ctrl+C, sans jamais laisser sa chance au double Ctrl+C.
            println!(
                "[main] Séquence annulée — {}s d'attente avant redémarrage (double Ctrl+C = arrêt total)...",
                DOUBLE_CTRLC_WINDOW.as_secs()
            );
            let deadline = Instant::now() + DOUBLE_CTRLC_WINDOW;
            while Instant::now() < deadline && !stop_flag.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }

            if stop_flag.load(Ordering::SeqCst) {
                continue;
            }

            println!("[main] Redémarrage NOS3 avant de continuer...");
            nos3_control::restart_nos3();
        }
    }
}
