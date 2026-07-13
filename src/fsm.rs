use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct FsmTransition {
    pub from:      String,
    pub to:        String,
    pub tc_fc:     u8,
    pub tc_name:   String,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default = "default_true")]
    pub fuzz:      bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AlwaysValidCmd {
    pub tc_fc:  u8,
    pub tc_name: String,
    #[serde(default = "default_true")]
    pub fuzz:   bool,
}

#[derive(Debug, Deserialize)]
pub struct AppFsmDef {
    pub app_name:             String,
    pub msgid:                String,
    #[serde(default)]
    pub stateless:            bool,
    #[serde(default)]
    pub states:               Vec<String>,
    #[serde(default)]
    pub transitions:          Vec<FsmTransition>,
    #[serde(default)]
    pub commands_always_valid: Vec<AlwaysValidCmd>,
}

fn default_true() -> bool { true }

// ─── Runtime ─────────────────────────────────────────────────────────────────

pub struct FsmRuntime {
    pub fsms:    HashMap<String, AppFsmDef>,
    current:     HashMap<String, String>,   // app → current state
    initial:     HashMap<String, String>,   // app → initial state
    tc_to_app:   HashMap<String, String>,   // tc_name → app
}

impl FsmRuntime {
    pub fn load(fsm_dir: &str) -> Self {
        let mut fsms: HashMap<String, AppFsmDef> = HashMap::new();

        let entries = std::fs::read_dir(fsm_dir)
            .unwrap_or_else(|e| panic!("Cannot read FSM dir {fsm_dir}: {e}"));

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Cannot read {path:?}: {e}"));
            match serde_yaml::from_str::<AppFsmDef>(&content) {
                Ok(def) => { fsms.insert(def.app_name.to_uppercase(), def); }
                Err(e)  => eprintln!("[fsm] skip {path:?}: {e}"),
            }
        }

        let mut current   = HashMap::new();
        let mut initial   = HashMap::new();
        let mut tc_to_app = HashMap::new();

        for (name, def) in &fsms {
            let init = def.states.first()
                .cloned()
                .unwrap_or_else(|| "STATELESS".to_string());
            current.insert(name.clone(), init.clone());
            initial.insert(name.clone(), init);

            for t in &def.transitions {
                tc_to_app.insert(t.tc_name.clone(), name.clone());
            }
            for c in &def.commands_always_valid {
                tc_to_app.entry(c.tc_name.clone()).or_insert_with(|| name.clone());
            }
        }

        Self { fsms, current, initial, tc_to_app }
    }

    pub fn app_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.fsms.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn current_state(&self, app: &str) -> &str {
        self.current.get(app).map(|s| s.as_str()).unwrap_or("UNKNOWN")
    }

    pub fn valid_transitions(&self, app: &str) -> Vec<&FsmTransition> {
        let fsm   = match self.fsms.get(app) { Some(f) => f, None => return vec![] };
        let state = self.current_state(app);
        fsm.transitions.iter().filter(|t| t.from == state).collect()
    }

    pub fn always_valid(&self, app: &str) -> &[AlwaysValidCmd] {
        self.fsms.get(app)
            .map(|f| f.commands_always_valid.as_slice())
            .unwrap_or(&[])
    }

    /// Avance (ou reset) l'état FSM après une exécution.
    pub fn advance(&mut self, tc_name: &str, verdict: &str) {
        let app = match self.tc_to_app.get(tc_name).cloned() {
            Some(a) => a,
            None    => return,
        };

        match verdict {
            "TIMEOUT" | "CRASH" => {
                if let Some(init) = self.initial.get(&app).cloned() {
                    self.current.insert(app, init);
                }
            }
            "OK" => {
                let fsm     = match self.fsms.get(&app) { Some(f) => f, None => return };
                let current = self.current.get(&app).cloned().unwrap_or_default();
                for t in &fsm.transitions {
                    if t.from == current && t.tc_name == tc_name {
                        let next = t.to.clone();
                        self.current.insert(app, next);
                        return;
                    }
                }
            }
            _ => {} // DROP_* → reste dans l'état courant
        }
    }
}

pub type SharedFsm = Arc<Mutex<FsmRuntime>>;

pub fn load_shared(fsm_dir: &str) -> SharedFsm {
    Arc::new(Mutex::new(FsmRuntime::load(fsm_dir)))
}
