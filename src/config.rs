use serde::Deserialize;

use crate::input::{FixedField, MutatorKind};

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    /// Une seule app ciblée (apps = ["ES"])
    SingleApp,
    /// Plusieurs apps ciblées (apps = ["ES", "CF", ...])
    MultiApp,
    /// Toutes les TC du catalogue, une par séquence
    All,
    /// Séquences qui mixent des TC de différentes apps
    CrossApp,
    /// Flood naif : pas de feedback, environ 110 pkt/sec
    Naive,
    /// Guidé par machine d'états : lit les FSM YAMLs de maya3
    Stateful,
}

#[derive(Deserialize, Debug)]
pub struct FuzzConfig {
    pub mode: FuzzMode,

    /// Apps à cibler — utilisé uniquement pour single_app et multi_app
    #[serde(default)]
    pub apps: Vec<String>,

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

    /// Mutateur(s) actifs pendant le fuzzing, choisis dans la liste proposée
    ///.Une seule entrée => ce mutateur est utilisé pour tous les paquets mutés. 
    // Plusieurs entrées => un mutateur est tiré au hasard dans cette liste à chaque paquet muté.
    // Absent → tous les mutateurs disponibles sont utilisés (tirage aléatoire parmi tous).
    #[serde(default = "default_mutators")]
    pub mutators: Vec<MutatorKind>,
}

fn default_naive_batch() -> usize  { 10 }
fn default_cross_min()   -> usize  { 2 }
fn default_cross_max()   -> usize  { 5 }
fn default_fsm_dir()     -> String {
    "fsm".to_string()
}
fn default_mutators()    -> Vec<MutatorKind> { MutatorKind::ALL.to_vec() }

pub fn load(path: &str) -> FuzzConfig {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!(
            "Impossible de lire {path}: {e}\n\
             => Vérifie que fuzz_config.toml est présent à la racine du projet"
        ));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("TOML invalide dans {path}: {e}"))
}

/// Fichier passé via `--fixed-fields <path>` : liste de champs à figer en
/// post-processing, juste après la mutation automatique (voir
/// input::FixedFieldsMutator / ChainMutator).
#[derive(Deserialize, Debug)]
struct FixedFieldsFile {
    #[serde(default)]
    fixed: Vec<FixedField>,
}

/// Charge un fichier `--fixed-fields`. Panics avec un message clair si le
/// fichier est absent ou malformé (contrairement à `load()`, ce fichier est
/// optionnel côté CLI — l'appel n'a lieu que si `--fixed-fields` a été passé).
pub fn load_fixed_fields(path: &str) -> Vec<FixedField> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Impossible de lire {path}: {e}"));
    let parsed: FixedFieldsFile = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("TOML invalide dans {path}: {e}"));
    parsed.fixed
}
