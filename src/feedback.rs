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

use crate::input::CcsdsSequenceInput;

/// Juge "intéressant" tout couple (tc_name, verdict) jamais observé auparavant.
///
/// Pourquoi pas verdict seul ?
///   NOS3 ne produit que ~5 verdicts distincts (OK / DROP_* / TIMEOUT / CRASH).
///   Dès que les premières seeds couvrent ces 5 cas, plus rien n'est "nouveau"
///   et le corpus ne grandit plus. En incluant le nom de la TC dans la clé on
///   distingue "CFE_ES_NOOP_CC:OK" de "CFE_TIME_NOOP_CC:OK" — le corpus peut
///   alors croître jusqu'à N_TC × N_verdicts entrées utiles.
pub struct Nos3Feedback {
    seen: HashSet<String>,
    stdout_handle: Handle<StdOutObserver>,
}

impl Nos3Feedback {
    pub fn new(stdout_handle: Handle<StdOutObserver>) -> Self {
        Self { seen: HashSet::new(), stdout_handle }
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

        // Clé = "CFE_ES_RESTART_CC:DROP_LEN_MISMATCH" — granularité par commande
        let key = format!("{tc_name}:{verdict}");
        Ok(self.seen.insert(key))
    }
}

impl Named for Nos3Feedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("Nos3Feedback")
    }
}
