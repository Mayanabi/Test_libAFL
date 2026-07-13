use std::borrow::Cow;
use std::collections::HashSet;

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
}

impl Nos3Feedback {
    pub fn new(stdout_handle: Handle<StdOutObserver>) -> Self {
        Self { seen: HashSet::new(), stdout_handle, fsm: None }
    }

    pub fn new_with_fsm(stdout_handle: Handle<StdOutObserver>, fsm: SharedFsm) -> Self {
        Self { seen: HashSet::new(), stdout_handle, fsm: Some(fsm) }
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
