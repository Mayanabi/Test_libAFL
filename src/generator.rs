use std::collections::HashMap;

use libafl::{generators::Generator, state::HasRand, Error};
use libafl_bolts::rands::Rand;

use crate::catalogue::{Catalogue, CatalogueArg, CatalogueEntry};
use crate::fsm::SharedFsm;
use crate::input::{ArgType, CcsdsArg, CcsdsCommand, CcsdsSequenceInput, Endianness};

// ─── Helpers partagés ────────────────────────────────────────────────────────

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

/// Construit une CcsdsCommand à partir d'un template du catalogue — exposé
/// pour être réutilisé par le binaire send_packet (envoi manuel hors séquence).
pub fn build_command(name: &str, tpl: &CatalogueEntry, step: i32) -> CcsdsCommand {
    CcsdsCommand {
        step,
        tc_name:      name.to_owned(),
        fuzz:         true,
        mandatory:    false,
        delay_min_ms: 0,
        delay_max_ms: 0,
        args:         tpl.args.iter().map(convert_arg).collect(),
        target:       tpl.target.clone(),
        port:         tpl.port,
        mutation:     "havoc".into(),
        replay:       false,
    }
}

// ─── CatalogueGenerator ──────────────────────────────────────────────────────

pub struct CatalogueGenerator {
    catalogue:    Catalogue,
    keys:         Vec<String>,
    keys_by_app:  HashMap<String, Vec<String>>,
    /// Some((min, max)) → mode cross_app
    cross_app:    Option<(usize, usize)>,
    /// Some(n) → mode naive : génère n commandes par séquence sans attendre le feedback
    naive_batch:  Option<usize>,
    /// true → mode all : une séquence = une TC par app (ordre alphabétique
    /// des apps), TC choisie au hasard dans chaque app.
    all_ordered:  bool,
}

impl CatalogueGenerator {
    pub fn new(catalogue: Catalogue) -> Self {
        let keys = catalogue.keys().cloned().collect();
        let mut keys_by_app: HashMap<String, Vec<String>> = HashMap::new();
        for (name, entry) in &catalogue {
            keys_by_app.entry(entry.app.clone()).or_default().push(name.clone());
        }
        Self { catalogue, keys, keys_by_app, cross_app: None, naive_batch: None, all_ordered: false }
    }

    pub fn with_cross_app(mut self, min_tc: usize, max_tc: usize) -> Self {
        self.cross_app = Some((min_tc, max_tc));
        self
    }

    /// Active le mode all : chaque séquence contient une commande par app du
    /// catalogue (ordre alphabétique des apps), la TC étant tirée au hasard
    /// dans chaque app à chaque appel de generate().
    pub fn with_all_ordered(mut self) -> Self {
        self.all_ordered = true;
        self
    }

    /// Active le mode naive : `batch_size` commandes aléatoires par séquence,
    /// sans poll du feedback (wrapper.py ne poll pas le log en mode FUZZ_MODE=naive).
    pub fn with_naive_batch(mut self, batch_size: usize) -> Self {
        self.naive_batch = Some(batch_size.max(1));
        self
    }
}

impl<S: HasRand> Generator<CcsdsSequenceInput, S> for CatalogueGenerator {
    fn generate(&mut self, state: &mut S) -> Result<CcsdsSequenceInput, Error> {
        if self.keys.is_empty() {
            return Err(Error::illegal_state(
                "CatalogueGenerator vide — vérifier catalogue_dump.json"
            ));
        }

        // Mode naive : batch de N commandes aléatoires, pas de délai
        if let Some(batch) = self.naive_batch {
            let rng = state.rand_mut();
            let commands = (1..=batch)
                .map(|step| {
                    let idx  = rng.next() as usize % self.keys.len();
                    let name = &self.keys[idx];
                    let tpl  = &self.catalogue[name];
                    build_command(name, tpl, step as i32)
                })
                .collect();
            return Ok(CcsdsSequenceInput { commands });
        }

        // Mode cross_app
        if let Some((min_tc, max_tc)) = self.cross_app {
            return Ok(self.generate_cross_app(state, min_tc, max_tc));
        }

        // Mode all : une TC par app, ordre alphabétique des apps
        if self.all_ordered {
            return Ok(self.generate_all_ordered(state));
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
    fn generate_cross_app<S: HasRand>(&self, state: &mut S, min_tc: usize, max_tc: usize) -> CcsdsSequenceInput {
        let mut app_names: Vec<&String> = self.keys_by_app.keys().collect();
        app_names.sort();

        let n_apps = app_names.len();
        let rng    = state.rand_mut();

        let span = if max_tc > min_tc { max_tc - min_tc } else { 0 };
        let n_tc = (min_tc + rng.next() as usize % (span + 1)).min(n_apps);

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

    /// Mode all : une séquence = une commande par app du catalogue, envoyées
    /// dans l'ordre alphabétique des apps (ordre stable d'une exécution à
    /// l'autre). La TC précise est tirée au hasard dans chaque app, pour
    /// varier la couverture sans changer l'app ni l'ordre d'envoi.
    fn generate_all_ordered<S: HasRand>(&self, state: &mut S) -> CcsdsSequenceInput {
        let mut app_names: Vec<&String> = self.keys_by_app.keys().collect();
        app_names.sort();

        let rng = state.rand_mut();
        let mut commands = Vec::with_capacity(app_names.len());
        for (step, app) in app_names.iter().enumerate() {
            let keys = &self.keys_by_app[*app];
            let name = keys[rng.next() as usize % keys.len()].clone();
            let tpl  = &self.catalogue[&name];
            commands.push(build_command(&name, tpl, step as i32 + 1));
        }

        CcsdsSequenceInput { commands }
    }
}

// ─── StatefulGenerator ───────────────────────────────────────────────────────

/// Génère des commandes guidées par la machine d'états de chaque app NOS3.
///
/// À chaque appel, choisit aléatoirement une app, lit son état courant dans
/// la FSM partagée, et sélectionne une commande valide pour cet état.
/// Le feedback (Nos3Feedback) fait avancer la FSM après chaque exécution.
pub struct StatefulGenerator {
    catalogue:  Catalogue,
    keys:       Vec<String>,           // fallback : toutes les clés
    fsm:        SharedFsm,
    app_names:  Vec<String>,           // apps qui ont une FSM chargée
}

impl StatefulGenerator {
    pub fn new(catalogue: Catalogue, fsm: SharedFsm) -> Self {
        let keys      = catalogue.keys().cloned().collect();
        let app_names = fsm.lock().unwrap().app_names();
        Self { catalogue, keys, fsm, app_names }
    }
}

impl<S: HasRand> Generator<CcsdsSequenceInput, S> for StatefulGenerator {
    fn generate(&mut self, state: &mut S) -> Result<CcsdsSequenceInput, Error> {
        if self.app_names.is_empty() {
            return Err(Error::illegal_state("StatefulGenerator: aucun FSM chargé"));
        }

        let rng = state.rand_mut();

        // Essaie plusieurs apps pour en trouver une avec des commandes valides dans le catalogue
        for _ in 0..20 {
            let app = &self.app_names[rng.next() as usize % self.app_names.len()];

            // Commandes valides = transitions depuis l'état courant + toujours valides
            let mut candidates: Vec<(String, bool)> = vec![];
            {
                let runtime = self.fsm.lock().unwrap();
                for t in runtime.valid_transitions(app) {
                    candidates.push((t.tc_name.clone(), t.fuzz));
                }
                for c in runtime.always_valid(app) {
                    candidates.push((c.tc_name.clone(), c.fuzz));
                }
            }

            if candidates.is_empty() {
                continue;
            }

            let (tc_name, fuzz_flag) = candidates[rng.next() as usize % candidates.len()].clone();

            if let Some(tpl) = self.catalogue.get(&tc_name) {
                let mut cmd = build_command(&tc_name, tpl, 1);
                cmd.fuzz = fuzz_flag;
                return Ok(CcsdsSequenceInput { commands: vec![cmd] });
            }
        }

        // Fallback : commande aléatoire du catalogue
        let name = self.keys[rng.next() as usize % self.keys.len()].clone();
        let tpl  = &self.catalogue[&name];
        Ok(CcsdsSequenceInput { commands: vec![build_command(&name, tpl, 1)] })
    }
}
