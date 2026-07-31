//! Envoi manuel d'un paquet CCSDS unique à NOS3, hors séquence et hors boucle
//! LibAFL — pour tester un paquet fait main (faux flags, valeurs précises...)
//! en dehors de la mutation automatique.
//!
//! Usage : cargo run --bin send_packet [-- chemin/vers/spec.toml]
//! (par défaut : one_shot.toml à la racine du projet)

use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;

use maya_libafl_poc::{catalogue, generator, input::CcsdsSequenceInput};

#[derive(Deserialize, Debug)]
struct OneShotSpec {
    /// Template de départ dans catalogue_dump.json (fournit port/target/args par défaut).
    tc_name: String,
    #[serde(default)]
    overrides: Vec<FieldOverride>,
    delay_min_ms: Option<u32>,
    delay_max_ms: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct FieldOverride {
    /// Nom de l'arg tel qu'il apparaît dans catalogue_dump.json (ID, SEQ, LEN,
    /// FC, CHECKSUM, ou un argument applicatif du TC).
    name:  String,
    /// Valeur brute envoyée telle quelle (ex: "0xFF", "1234", "toto").
    value: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).map(String::as_str).unwrap_or("one_shot.toml");

    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Impossible de lire {path}: {e}"));
    let spec: OneShotSpec = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("TOML invalide dans {path}: {e}"));

    let cat = catalogue::load("catalogue_dump.json");
    let tpl = cat.get(&spec.tc_name).unwrap_or_else(|| {
        panic!("TC '{}' introuvable dans catalogue_dump.json", spec.tc_name)
    });

    let mut cmd = generator::build_command(&spec.tc_name, tpl, 1);
    if let Some(v) = spec.delay_min_ms { cmd.delay_min_ms = v; }
    if let Some(v) = spec.delay_max_ms { cmd.delay_max_ms = v; }

    for ov in &spec.overrides {
        match cmd.args.iter_mut().find(|a| a.name.eq_ignore_ascii_case(&ov.name)) {
            Some(arg) => arg.value = ov.value.clone().into_bytes(),
            None => eprintln!(
                "[send_packet] champ '{}' introuvable dans {} — ignoré",
                ov.name, spec.tc_name
            ),
        }
    }

    let port = cmd.port;
    let seq  = CcsdsSequenceInput { commands: vec![cmd] };
    let json = serde_json::to_vec(&seq).expect("serialization should not fail");

    println!("[send_packet] envoi de {} (port {port}) :", spec.tc_name);
    println!("{}", String::from_utf8_lossy(&json));

    let mut child = Command::new("python3")
        .arg("wrapper.py")
        .env("FUZZ_MODE", "normal")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("impossible de lancer wrapper.py");

    child.stdin.take().expect("stdin was piped")
        .write_all(&json)
        .expect("écriture stdin échouée");

    let output = child.wait_with_output().expect("échec de wrapper.py");
    println!("[send_packet] verdict : {}", String::from_utf8_lossy(&output.stdout).trim());
}
