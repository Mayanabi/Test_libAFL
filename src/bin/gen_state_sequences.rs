//! Génère state_sequences/<APP>.json pour chaque FSM de fsm/ qui n'en a pas
//! encore — même format que les fichiers déjà présents (NOVATEL_OEM615.json,
//! ARDUCAM.json, CF.json), utilisable directement avec `--component`.
//!
//! Algorithme : parcourt le graphe de la FSM depuis son état initial en
//! empruntant chaque transition au moins une fois (en repassant par des
//! transitions déjà utilisées si besoin pour rejoindre un état qui a encore
//! des transitions inexplorées), puis insère les commandes
//! `commands_always_valid` juste après le dernier passage dans l'état
//! mentionné dans leur `notes` (ex: "Requires ENABLED") — ou à la fin de la
//! séquence si aucun état n'y est mentionné.
//!
//! C'est heuristique (le champ `notes` est du texte libre) : à vérifier avec
//! `--component <APP> --show` avant de s'y fier pour de vrai, contrairement
//! aux 3 fichiers existants qui ont été construits/relus à la main.
//!
//! Usage : cargo run --bin gen_state_sequences [APP...]   (défaut : toutes les FSM sans fichier existant)
//!         cargo run --bin gen_state_sequences -- --force  (régénère aussi celles qui existent déjà)

use maya_libafl_poc::{catalogue, fsm, generator};
use maya_libafl_poc::catalogue::Catalogue;
use maya_libafl_poc::fsm::{AlwaysValidCmd, AppFsmDef, FsmTransition};
use maya_libafl_poc::input::CcsdsSequenceInput;

use std::collections::{HashMap, HashSet, VecDeque};

const FSM_DIR: &str = "fsm";
const OUT_DIR: &str = "state_sequences";

fn main() {
    let raw_cat = catalogue::load("catalogue_dump.json");
    let runtime = fsm::FsmRuntime::load(FSM_DIR);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let force = args.iter().any(|a| a == "--force");
    let only: Option<HashSet<String>> = {
        let names: Vec<String> = args.iter().filter(|a| *a != "--force").cloned().collect();
        if names.is_empty() { None } else { Some(names.into_iter().map(|s| s.to_uppercase()).collect()) }
    };

    let mut apps: Vec<&String> = runtime.fsms.keys().collect();
    apps.sort();

    for app in apps {
        if let Some(only) = &only {
            if !only.contains(app) { continue; }
        }
        let out_path = format!("{OUT_DIR}/{app}.json");
        if !force && std::path::Path::new(&out_path).exists() {
            println!("[gen] {app} : {out_path} existe déjà, ignoré (--force pour régénérer)");
            continue;
        }

        let def   = &runtime.fsms[app];
        let notes = extract_notes(&format!("{FSM_DIR}/{}_fsm.yaml", app.to_lowercase()));

        match build_sequence(&raw_cat, def, &notes) {
            Ok(seq) => {
                let json = serde_json::to_string_pretty(&seq).expect("sérialisation JSON");
                std::fs::write(&out_path, json).unwrap_or_else(|e| panic!("écriture {out_path}: {e}"));
                println!("[gen] {app} : {out_path} ({} étape(s))", seq.commands.len());
            }
            Err(e) => eprintln!("[gen] {app} : ignoré — {e}"),
        }
    }
}

/// Relit le YAML en `serde_yaml::Value` (indépendamment de `fsm::AppFsmDef`,
/// qui n'expose pas `notes`) pour associer tc_name → texte de note.
fn extract_notes(path: &str) -> HashMap<String, String> {
    let mut notes = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else { return notes };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&text) else { return notes };
    for key in ["transitions", "commands_always_valid"] {
        if let Some(seq) = val.get(key).and_then(|v| v.as_sequence()) {
            for item in seq {
                if let (Some(tc_name), Some(note)) = (
                    item.get("tc_name").and_then(|v| v.as_str()),
                    item.get("notes").and_then(|v| v.as_str()),
                ) {
                    notes.insert(tc_name.to_string(), note.to_string());
                }
            }
        }
    }
    notes
}

fn build_sequence(
    cat: &Catalogue,
    def: &AppFsmDef,
    notes: &HashMap<String, String>,
) -> Result<CcsdsSequenceInput, String> {
    let start = def.states.first().ok_or("aucun état déclaré (states: [])")?.clone();

    let walk = walk_all_transitions(def, &start);

    // Dernier index dans `walk` où l'on entre dans chaque état (walk[i].to).
    let mut last_entry: HashMap<&str, usize> = HashMap::new();
    for (i, t) in walk.iter().enumerate() {
        last_entry.insert(t.to.as_str(), i);
    }

    // NOOP (s'il existe) part en tête, fuzz=false ; le reste des
    // commands_always_valid est trié dans des "seaux" d'insertion —
    // seau[0] = avant toute transition, seau[i+1] = juste après walk[i].
    let mut noop: Option<&AlwaysValidCmd> = None;
    let mut buckets: Vec<Vec<&AlwaysValidCmd>> = vec![Vec::new(); walk.len() + 1];
    for c in &def.commands_always_valid {
        if noop.is_none() && c.tc_name.to_uppercase().contains("NOOP") {
            noop = Some(c);
            continue;
        }
        let required_state = notes.get(&c.tc_name).and_then(|n| find_required_state(n, &def.states));
        let slot = match required_state {
            Some(s) if s == start && !last_entry.contains_key(s) => 0,
            Some(s) => last_entry.get(s).map(|i| i + 1).unwrap_or(walk.len()),
            None => walk.len(),
        };
        buckets[slot].push(c);
    }
    for b in &mut buckets {
        b.sort_by_key(|c| c.tc_fc);
    }

    // Assemblage final : NOOP, seau[0], walk[0], seau[1], walk[1], seau[2], ...
    let mut commands = Vec::new();
    let mut push_cmd = |tc_name: &str, fuzz: bool| -> Result<(), String> {
        let tpl = cat.get(tc_name).ok_or_else(|| format!(
            "{tc_name} absente de catalogue_dump.json (régénère-le avec dump_catalogue.py si le YAML a changé)"
        ))?;
        let mut cmd = generator::build_command(tc_name, tpl, commands.len() as i32 + 1);
        cmd.fuzz = fuzz;
        cmd.delay_min_ms = 300;
        cmd.delay_max_ms = 300;
        commands.push(cmd);
        Ok(())
    };

    if let Some(c) = noop {
        push_cmd(&c.tc_name, false)?;
    }
    for c in &buckets[0] {
        push_cmd(&c.tc_name, true)?;
    }
    for (i, t) in walk.iter().enumerate() {
        push_cmd(&t.tc_name, true)?;
        for c in &buckets[i + 1] {
            push_cmd(&c.tc_name, true)?;
        }
    }

    if commands.is_empty() {
        return Err("aucune commande générée (FSM vide ?)".to_string());
    }
    // Dernière étape : pas de délai supplémentaire (mêmes conventions que les
    // fichiers state_sequences/ existants).
    let last = commands.len() - 1;
    commands[last].delay_min_ms = 0;
    commands[last].delay_max_ms = 0;

    Ok(CcsdsSequenceInput { commands })
}

/// Cherche un nom d'état de la FSM mentionné (en toutes lettres) dans un
/// texte de note libre — ex: "Requires ENABLED" → Some("ENABLED"). Teste les
/// noms d'état les plus longs en premier pour éviter les matches ambigus.
fn find_required_state<'a>(text: &str, states: &'a [String]) -> Option<&'a str> {
    let upper = text.to_uppercase();
    let mut candidates: Vec<&String> = states.iter().collect();
    candidates.sort_by_key(|s| std::cmp::Reverse(s.len()));
    candidates.into_iter().find(|s| upper.contains(s.as_str())).map(|s| s.as_str())
}

/// Parcourt toutes les transitions de la FSM au moins une fois en partant de
/// `start`, en respectant la contrainte from == état courant à chaque étape.
/// Quand l'état courant n'a plus de transition inexplorée mais qu'il en
/// reste ailleurs dans le graphe, rejoint le plus proche état qui en a une
/// via le plus court chemin (sur l'ensemble des transitions, y compris déjà
/// utilisées — les repasser est un envoi de commande valide, pas un souci).
fn walk_all_transitions<'a>(def: &'a AppFsmDef, start: &str) -> Vec<&'a FsmTransition> {
    let mut remaining: Vec<&FsmTransition> = def.transitions.iter().collect();
    let mut walk: Vec<&FsmTransition> = Vec::new();
    let mut current = start.to_string();

    while !remaining.is_empty() {
        if let Some(pos) = remaining.iter().position(|t| t.from == current) {
            let t = remaining.remove(pos);
            current = t.to.clone();
            walk.push(t);
            continue;
        }

        let target = remaining[0].from.clone();
        match shortest_path(def, &current, &target) {
            Some(path) => {
                for t in path {
                    current = t.to.clone();
                    walk.push(t);
                }
            }
            None => {
                eprintln!(
                    "[gen] {} : {} transition(s) ignorée(s) — état '{target}' inatteignable depuis '{current}' (graphe déconnecté)",
                    def.app_name, remaining.len()
                );
                break;
            }
        }
    }
    walk
}

fn shortest_path<'a>(def: &'a AppFsmDef, from: &str, to: &str) -> Option<Vec<&'a FsmTransition>> {
    if from == to {
        return Some(vec![]);
    }
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(from);
    let mut came_from: HashMap<&str, (&str, &FsmTransition)> = HashMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(from);

    while let Some(state) = queue.pop_front() {
        if state == to {
            break;
        }
        for t in &def.transitions {
            if t.from == state && visited.insert(t.to.as_str()) {
                came_from.insert(&t.to, (state, t));
                queue.push_back(&t.to);
            }
        }
    }

    if !visited.contains(to) {
        return None;
    }
    let mut path = Vec::new();
    let mut cur = to;
    while cur != from {
        let (f, t) = *came_from.get(cur)?;
        path.push(t);
        cur = f;
    }
    path.reverse();
    Some(path)
}
