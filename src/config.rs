use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    /// Une ou plusieurs apps NOS3 ciblées (apps = [...])
    SingleApp,
    MultiApp,
    /// Toutes les TC du catalogue (~315 TC), une par séquence
    All,
    /// Séquences qui mixent des TC de différentes apps aléatoires
    CrossApp,
}

#[derive(Deserialize, Debug)]
pub struct FuzzConfig {
    pub mode: FuzzMode,

    /// Apps à cibler — ignoré si mode = "all" ou "cross_app"
    #[serde(default)]
    pub apps: Vec<String>,

    /// Filtre de priorité optionnel : "CRITICAL" | "HIGH" | "MEDIUM" | "NORMAL"
    pub fuzz_priority: Option<String>,

    /// Nombre de seeds initiales
    #[serde(default = "default_seed_count")]
    pub seed_count: usize,

    /// Nombre minimum de TC dans une séquence cross-app (défaut 2)
    #[serde(default = "default_cross_min")]
    pub cross_app_min_tc: usize,

    /// Nombre maximum de TC dans une séquence cross-app (défaut 5)
    #[serde(default = "default_cross_max")]
    pub cross_app_max_tc: usize,
}

fn default_seed_count() -> usize { 8 }
fn default_cross_min()   -> usize { 2 }
fn default_cross_max()   -> usize { 5 }

pub fn load(path: &str) -> FuzzConfig {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!(
            "Impossible de lire {path}: {e}\n\
             → Vérifie que fuzz_config.toml est présent à la racine du projet"
        ));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("TOML invalide dans {path}: {e}"))
}
