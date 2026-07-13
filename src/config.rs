use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    /// Une seule app ciblée (apps = ["ES"])
    SingleApp,
    /// Plusieurs apps ciblées (apps = ["ES", "CF", ...])
    MultiApp,
    /// Toutes les TC du catalogue (~315 TC), une par séquence
    All,
    /// Séquences qui mixent des TC de différentes apps
    CrossApp,
    /// Flood naïf — pas de feedback, ~110 pkt/sec
    Naive,
    /// Guidé par machine d'états — lit les FSM YAMLs de maya3
    Stateful,
}

#[derive(Deserialize, Debug)]
pub struct FuzzConfig {
    pub mode: FuzzMode,

    /// Apps à cibler — utilisé uniquement pour single_app et multi_app
    #[serde(default)]
    pub apps: Vec<String>,

    /// Filtre de priorité optionnel : "CRITICAL" | "HIGH" | "MEDIUM" | "NORMAL"
    pub fuzz_priority: Option<String>,

    /// Nombre de seeds initiales
    #[serde(default = "default_seed_count")]
    pub seed_count: usize,

    /// Taille du batch en mode naive (commandes par subprocess)
    #[serde(default = "default_naive_batch")]
    pub naive_batch_size: usize,

    /// Nombre minimum de TC dans une séquence cross_app
    #[serde(default = "default_cross_min")]
    pub cross_app_min_tc: usize,

    /// Nombre maximum de TC dans une séquence cross_app
    #[serde(default = "default_cross_max")]
    pub cross_app_max_tc: usize,

    /// Répertoire contenant les FSM YAMLs (mode stateful uniquement)
    #[serde(default = "default_fsm_dir")]
    pub fsm_dir: String,
}

fn default_seed_count()  -> usize  { 8 }
fn default_naive_batch() -> usize  { 10 }
fn default_cross_min()   -> usize  { 2 }
fn default_cross_max()   -> usize  { 5 }
fn default_fsm_dir()     -> String {
    "/home/jstar/Desktop/maya3/patterns/stateful".to_string()
}

pub fn load(path: &str) -> FuzzConfig {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!(
            "Impossible de lire {path}: {e}\n\
             → Vérifie que fuzz_config.toml est présent à la racine du projet"
        ));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("TOML invalide dans {path}: {e}"))
}
