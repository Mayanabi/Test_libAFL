//! Catalogue de séquences d'état par composant (state_sequences/<COMPOSANT>.json)
//! — chaque fichier est une suite de commandes ORDONNÉE qui amène un
//! composant dans un état valide connu (ex: NOVATEL_OEM615 : NOOP → ENABLE →
//! LOG → UNLOG → RST_COUNTERS → DISABLE). Utilisé par le fuzzing normal
//! (cargo run -- --component ...) pour partir d'une séquence connue plutôt
//! que d'une génération aléatoire depuis catalogue_dump.json.

use crate::input::CcsdsSequenceInput;

pub const STATE_SEQUENCES_DIR: &str = "state_sequences";

/// Affiche les composants disponibles dans le catalogue (nom de fichier sans
/// extension = nom du composant à passer à --component).
pub fn list_components() {
    println!("Composants disponibles dans {STATE_SEQUENCES_DIR}/ :");
    let entries = std::fs::read_dir(STATE_SEQUENCES_DIR).unwrap_or_else(|e| {
        panic!("Impossible de lire {STATE_SEQUENCES_DIR}/: {e}")
    });
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    if names.is_empty() {
        println!("  (aucun — ajoute un fichier {STATE_SEQUENCES_DIR}/<COMPOSANT>.json)");
    }
    for name in names {
        println!("  - {name}");
    }
}

/// Charge state_sequences/<name>.json.
pub fn load_component(name: &str) -> CcsdsSequenceInput {
    let path = format!("{STATE_SEQUENCES_DIR}/{name}.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Impossible de lire {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("JSON invalide dans {path}: {e}"))
}

/// Force fuzz=false pour les étapes < start_step et fuzz=true à partir de
/// start_step (inclus) — override CLI, prioritaire sur les valeurs fuzz du
/// fichier JSON. Permet de repartir d'un état déjà atteint (ex: composant
/// déjà ENABLE) sans rééditer le catalogue à la main. Chaque mutateur
/// (voir input.rs) respecte cmd.fuzz, donc les étapes avant start_step ne
/// seront jamais mutées, même après clonage par le fuzzer.
pub fn apply_start_step(seq: &mut CcsdsSequenceInput, start_step: i32) {
    for cmd in &mut seq.commands {
        cmd.fuzz = cmd.step >= start_step;
    }
}

/// Affiche la séquence chargée (étape, TC, fuzz effectif) — pour vérifier
/// --start-step ou explorer un composant du catalogue avant de lancer un
/// vrai run.
pub fn print_sequence_preview(seq: &CcsdsSequenceInput) {
    println!("Séquence ({} étape(s)) :", seq.commands.len());
    for cmd in &seq.commands {
        let marker = if cmd.fuzz { "fuzz=true " } else { "fuzz=false" };
        println!("  étape {:<3} {marker}  {}", cmd.step, cmd.tc_name);
    }
}
