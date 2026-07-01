use std::collections::HashMap;

use libafl::{generators::Generator, state::HasRand, Error};
use libafl_bolts::rands::Rand;

use crate::catalogue::{Catalogue, CatalogueArg, CatalogueEntry};
use crate::input::{ArgType, CcsdsArg, CcsdsCommand, CcsdsSequenceInput, Endianness};

pub struct CatalogueGenerator {
    catalogue: Catalogue,
    /// Toutes les clés du catalogue filtré — tirage O(1) par index aléatoire.
    keys: Vec<String>,
    /// Clés groupées par app — utilisé en mode cross_app pour garantir
    /// qu'on pioche au plus une TC par app dans chaque séquence.
    keys_by_app: HashMap<String, Vec<String>>,
    /// Some((min, max)) active le mode cross-app.
    cross_app: Option<(usize, usize)>,
}

impl CatalogueGenerator {
    pub fn new(catalogue: Catalogue) -> Self {
        let keys = catalogue.keys().cloned().collect();
        let mut keys_by_app: HashMap<String, Vec<String>> = HashMap::new();
        for (name, entry) in &catalogue {
            keys_by_app.entry(entry.app.clone()).or_default().push(name.clone());
        }
        Self { catalogue, keys, keys_by_app, cross_app: None }
    }

    /// Active le mode cross-app : chaque séquence générée contiendra entre
    /// `min_tc` et `max_tc` TC provenant d'apps différentes.
    pub fn with_cross_app(mut self, min_tc: usize, max_tc: usize) -> Self {
        self.cross_app = Some((min_tc, max_tc));
        self
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_arg_type(s: &str) -> ArgType {
    match s {
        "INT"    => ArgType::Int,
        "FLOAT"  => ArgType::Float,
        "STRING" => ArgType::StringT,
        "BLOCK"  => ArgType::Block,
        _        => ArgType::UInt,
    }
}

fn to_endianness(s: &str) -> Option<Endianness> {
    match s {
        "BIG_ENDIAN"    => Some(Endianness::Big),
        "LITTLE_ENDIAN" => Some(Endianness::Little),
        _               => None,
    }
}

fn convert_arg(a: &CatalogueArg) -> CcsdsArg {
    CcsdsArg {
        name:       a.name.clone(),
        arg_type:   to_arg_type(&a.type_name),
        size_bits:  a.size.parse().unwrap_or(8),
        value:      a.value.as_bytes().to_vec(),
        endianness: to_endianness(&a.endianness),
    }
}

fn build_command(name: &str, tpl: &CatalogueEntry, step: i32) -> CcsdsCommand {
    CcsdsCommand {
        step,
        tc_name:      name.to_owned(),
        fuzz:         true,
        mandatory:    false,
        delay_min_ms: 0,
        delay_max_ms: 0,
        args:         tpl.args.iter().map(convert_arg).collect(),
        port:         tpl.port,
        target:       tpl.target.clone(),
        mutation:     "havoc".into(),
        replay:       false,
    }
}

// ─── Generator impl ──────────────────────────────────────────────────────────

impl<S: HasRand> Generator<CcsdsSequenceInput, S> for CatalogueGenerator {
    fn generate(&mut self, state: &mut S) -> Result<CcsdsSequenceInput, Error> {
        if self.keys.is_empty() {
            return Err(Error::illegal_state(
                "CatalogueGenerator vide — vérifier catalogue_dump.json"
            ));
        }

        if let Some((min_tc, max_tc)) = self.cross_app {
            return Ok(self.generate_cross_app(state, min_tc, max_tc));
        }

        // Mode normal : une seule TC par séquence
        let rng  = state.rand_mut();
        let idx  = rng.next() as usize % self.keys.len();
        let name = self.keys[idx].clone();
        let tpl  = &self.catalogue[&name];
        Ok(CcsdsSequenceInput { commands: vec![build_command(&name, tpl, 1)] })
    }
}

impl CatalogueGenerator {
    /// Génère une séquence cross-app : N TC choisies dans N apps différentes.
    ///
    /// Algorithme :
    ///   1. Collect les noms d'apps (ordre fixe pour indexation)
    ///   2. Fisher-Yates partiel pour sélectionner N apps sans répétition
    ///   3. Pour chaque app sélectionnée, tirer une TC aléatoire
    fn generate_cross_app<S: HasRand>(&self, state: &mut S, min_tc: usize, max_tc: usize) -> CcsdsSequenceInput {
        let mut app_names: Vec<&String> = self.keys_by_app.keys().collect();
        app_names.sort(); // ordre déterministe pour que l'index soit stable

        let n_apps = app_names.len();
        let rng    = state.rand_mut();

        // Nombre de TC à sélectionner (borné par le nombre d'apps dispo)
        let span = if max_tc > min_tc { max_tc - min_tc } else { 0 };
        let n_tc = (min_tc + rng.next() as usize % (span + 1)).min(n_apps);

        // Fisher-Yates partiel — mélange les n_tc premiers indices
        let mut indices: Vec<usize> = (0..n_apps).collect();
        for i in 0..n_tc {
            let j = i + rng.next() as usize % (n_apps - i);
            indices.swap(i, j);
        }

        let mut commands = Vec::with_capacity(n_tc);
        for (step, &app_idx) in indices[..n_tc].iter().enumerate() {
            let app  = app_names[app_idx];
            let keys = &self.keys_by_app[app];
            let name = keys[rng.next() as usize % keys.len()].clone();
            let tpl  = &self.catalogue[&name];
            commands.push(build_command(&name, tpl, step as i32 + 1));
        }

        CcsdsSequenceInput { commands }
    }
}
