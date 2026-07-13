use std::{
    io::Write,
    process::{Child, Command, Stdio},
    time::Duration,
};

use libafl::{
    executors::{command::CommandConfigurator, HasTimeout},
    Error,
};
use libafl_bolts::ownedref::OwnedSlice;
use libafl::observers::StdOutObserver;
use libafl_bolts::tuples::Handle;

/// Implémente CommandConfigurator pour notre pont vers NOS3 :
/// lance le wrapper Python, lui écrit les bytes de la séquence (JSON) sur stdin.
#[derive(Debug)]
pub struct Nos3Executor {
    pub wrapper_script: String,
    pub timeout: Duration,
    pub stdout_handle: Handle<StdOutObserver>,
    pub nos3_ip:   String,
    pub cfs_pid:   String,
    /// "naive" | "stateful" | "normal" — transmis à wrapper.py via FUZZ_MODE
    pub fuzz_mode: String,
}

impl Nos3Executor {
    pub fn new(
        wrapper_script: impl Into<String>,
        timeout: Duration,
        stdout_handle: Handle<StdOutObserver>,
        nos3_ip: impl Into<String>,
        cfs_pid: impl Into<String>,
        fuzz_mode: impl Into<String>,
    ) -> Self {
        Self {
            wrapper_script: wrapper_script.into(),
            timeout,
            stdout_handle,
            nos3_ip:   nos3_ip.into(),
            cfs_pid:   cfs_pid.into(),
            fuzz_mode: fuzz_mode.into(),
        }
    }
}

impl CommandConfigurator<Child> for Nos3Executor {
    fn spawn_child(&mut self, target_bytes: OwnedSlice<'_, u8>) -> Result<Child, Error> {
        let mut command = Command::new("python3");
        command
            .arg(&self.wrapper_script)
            .env("NOS3_IP",      &self.nos3_ip)
            .env("NOS3_CFS_PID", &self.cfs_pid)
            .env("FUZZ_MODE",    &self.fuzz_mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|e| {
            Error::illegal_state(format!("failed to spawn wrapper: {e}"))
        })?;

        // take() retire stdin du Child et le drop implicitement à la fin du bloc
        // → Python voit EOF immédiatement après l'écriture, sans attendre que
        // LibAFL décide de fermer le pipe de son côté.
        {
            let mut stdin = child.stdin.take().expect("stdin was piped");
            stdin
                .write_all(&target_bytes)
                .map_err(|e| Error::illegal_state(format!("failed to write stdin: {e}")))?;
        } // stdin dropped ici → EOF immédiat côté Python

        Ok(child)
        // Note : exit_kind_from_status() a une implémentation par défaut,
        // qu'on laisse pour l'instant — Crash si le process termine en erreur,
        // Ok sinon. On affinera plus tard si besoin (ex: code retour spécifique
        // pour distinguer un DROP_* d'un vrai crash du wrapper).
    }
    fn stdout_observer(&self) -> Option<Handle<StdOutObserver>> {
        Some(self.stdout_handle.clone())
    }
}

impl HasTimeout for Nos3Executor {
    fn timeout(&self) -> Duration {
        self.timeout
    }
}