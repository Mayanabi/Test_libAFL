use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use libafl::{
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::{ObserversTuple, StdOutObserver},
    Error,
};
use libafl_bolts::{tuples::Handle, Named};
use libafl_bolts::tuples::MatchNameRef;

use crate::fsm::SharedFsm;
use crate::input::CcsdsSequenceInput;

pub struct Nos3Feedback {
    seen:          HashSet<String>,
    stdout_handle: Handle<StdOutObserver>,
    /// En mode stateful : FSM partagée à faire avancer après chaque verdict.
    fsm:           Option<SharedFsm>,
    /// Mis à true par le handler Ctrl+C (main.rs) quand la séquence en cours
    /// vient d'être tuée par nous — son stdout est garbage/incomplet, pas un
    /// vrai signal NOS3. Consommé ici pour ne jamais l'ajouter au corpus.
    killed:        Arc<AtomicBool>,
}

impl Nos3Feedback {
    pub fn new(stdout_handle: Handle<StdOutObserver>, killed: Arc<AtomicBool>) -> Self {
        Self { seen: HashSet::new(), stdout_handle, fsm: None, killed }
    }

    pub fn new_with_fsm(
        stdout_handle: Handle<StdOutObserver>,
        fsm: SharedFsm,
        killed: Arc<AtomicBool>,
    ) -> Self {
        Self { seen: HashSet::new(), stdout_handle, fsm: Some(fsm), killed }
    }

    fn extract_verdict(output: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(output).ok()?;
        let line = text.lines().next()?;
        let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
        parsed.get("verdict")?.as_str().map(|s| s.to_string())
    }
}

impl<S> StateInitializer<S> for Nos3Feedback {}

impl<EM, OT, S> Feedback<EM, CcsdsSequenceInput, OT, S> for Nos3Feedback
where
    OT: ObserversTuple<CcsdsSequenceInput, S>,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &CcsdsSequenceInput,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        // Séquence tuée par le handler Ctrl+C (annulation) — pas un verdict
        // NOS3 exploitable, on ne l'ajoute jamais au corpus.
        if self.killed.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }

        let stdout_observer: &StdOutObserver = observers
            .get(&self.stdout_handle)
            .ok_or_else(|| Error::illegal_state("stdout observer not found"))?;

        let output = stdout_observer.output.as_ref()
            .ok_or_else(|| Error::illegal_state("no stdout captured"))?;

        let verdict = Self::extract_verdict(output)
            .unwrap_or_else(|| "PARSE_ERROR".to_string());

        let tc_name = input.commands.first()
            .map(|c| c.tc_name.as_str())
            .unwrap_or("UNKNOWN");

        // Mode stateful : avance la FSM selon le verdict reçu.
        // Le premier verdict dans une séquence multi-commandes suffit pour
        // les cas single-command du mode stateful.
        if let Some(fsm) = &self.fsm {
            // Pour une séquence multi-commandes, on avance pour chaque commande
            // en utilisant la partie du verdict qui lui correspond.
            let verdicts: Vec<&str> = verdict.split('|').collect();
            for (i, cmd) in input.commands.iter().enumerate() {
                let v = verdicts.get(i).copied().unwrap_or("UNKNOWN");
                fsm.lock().unwrap().advance(&cmd.tc_name, v);
            }
        }

        // Clé corpus = "CFE_ES_RESTART_CC:DROP_LEN_MISMATCH"
        let key = format!("{tc_name}:{verdict}");
        Ok(self.seen.insert(key))
    }
}

impl Named for Nos3Feedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("Nos3Feedback")
    }
}
