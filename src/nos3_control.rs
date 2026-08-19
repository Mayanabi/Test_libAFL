//! Démarrage/arrêt de NOS3 (make stop / make launch) — utilisé par main.rs
//! (redémarrage après Ctrl+C) et par hk_diff_test.rs (repartir d'un état
//! initial connu entre chaque phase, pour ne pas laisser le trafic bus d'une
//! phase polluer le comptage HK de la suivante).

use std::{
    fs::OpenOptions,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Répertoire du repo NOS3 (contient le Makefile : make stop / make launch).
pub const NOS3_DIR: &str = "/home/jstar/Desktop/github-nos3";
/// Temps max d'attente que cFS réponde après make launch.
pub const RESTART_WAIT: Duration = Duration::from_secs(90);
const RESTART_POLL: Duration = Duration::from_secs(2);
/// Chemin du log où atterrit la sortie (très verbeuse) de make stop/launch,
/// au lieu de spammer le terminal appelant à chaque redémarrage.
pub const NOS3_RESTART_LOG: &str = "/tmp/nos3_restart.log";

/// Retire les variables d'environnement injectées par VSCode (installé en
/// snap) qui redirigent GTK_PATH/GIO_MODULE_DIR/LOCPATH/etc. vers ses propres
/// libs bundlées. `make launch` invoque gnome-terminal en interne (une
/// fenêtre par conteneur, dont nos-fsw) ; avec ces variables héritées,
/// gnome-terminal.real plante avant même d'ouvrir une fenêtre (symbol lookup
/// error, conflit de version glibc) — make launch tourne alors sans qu'aucune
/// fenêtre n'apparaisse. Même correctif que _clean_env_for_gui() côté
/// wrapper.py (qui gère le cas crash cFS).
pub fn clean_env_for_gui(cmd: &mut Command) {
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

/// Variante non-panicking de la résolution du PID cFS, pour le polling
/// pendant un redémarrage — cFS n'est pas censé répondre tout de suite après
/// make launch.
fn try_resolve_cfs_pid() -> Option<String> {
    let out = Command::new("python3")
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

/// Arrête NOS3 (make stop) sans le relancer.
pub fn stop_nos3() {
    eprintln!("[nos3_control] arrêt de NOS3 (make stop)... (détails : {NOS3_RESTART_LOG})");
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
    eprintln!("[nos3_control] NOS3 arrêté.");
}

/// Redémarre NOS3 proprement (make stop && make launch) pour repartir d'un
/// état initial connu, puis bloque jusqu'à ce que cFS réponde de nouveau.
pub fn restart_nos3() {
    eprintln!(
        "[nos3_control] redémarrage NOS3 (make stop - make launch)... (détails : {NOS3_RESTART_LOG})"
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

    // make launch enveloppé dans gnome-terminal — sans ça les --tab émis à
    // l'intérieur de launch.sh n'atterrissent pas dans la même fenêtre quand
    // le process appelant n'est pas lui-même déjà rattaché à un terminal
    // ouvert par gnome-terminal.
    {
        let mut cmd = Command::new("gnome-terminal");
        cmd.arg(format!("--working-directory={NOS3_DIR}"))
            .arg("--")
            .arg("make")
            .arg("launch");
        clean_env_for_gui(&mut cmd);
        let _ = cmd.status();
    }

    eprintln!("[nos3_control] make launch lancé : attente cFS (max {}s)...", RESTART_WAIT.as_secs());
    let deadline = Instant::now() + RESTART_WAIT;
    while Instant::now() < deadline {
        if let Some(pid) = try_resolve_cfs_pid() {
            eprintln!("[nos3_control] NOS3 de nouveau disponible (PID={pid}), attente init...");
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        std::thread::sleep(RESTART_POLL);
    }
    eprintln!("[nos3_control] NOS3 toujours absent après {}s", RESTART_WAIT.as_secs());
}
