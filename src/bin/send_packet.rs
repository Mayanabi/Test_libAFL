//! Envoi manuel d'un paquet CCSDS unique à NOS3, hors séquence et hors boucle
//! LibAFL — pour tester un paquet fait main (faux flags, valeurs précises...)
//! en dehors de la mutation automatique.
//!
//! Usage : cargo run --bin send_packet [-- chemin/vers/spec.toml]
//! (par défaut : one_shot.toml à la racine du projet)

use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;

use maya_libafl_poc::{catalogue, generator, input};
use input::CcsdsSequenceInput;

#[derive(Deserialize, Debug)]
struct OneShotSpec {
    /// Template de départ dans catalogue_dump.json (fournit port/target/args par défaut).
    tc_name: String,
    /// Sous-champs du header CCSDS primaire (ID/SEQ), même granularité que
    /// les mutateurs 7-12 (VersionMutator, ApidMutator, ...).
    #[serde(default)]
    header: HeaderOverride,
    #[serde(default)]
    overrides: Vec<FieldOverride>,
    delay_min_ms: Option<u32>,
    delay_max_ms: Option<u32>,
}

/// Sous-champs du primary header CCSDS (48 bits, voir input.rs) — chacun
/// optionnel, seuls ceux présents dans le TOML sont modifiés, le reste vient
/// du template `tc_name`. Appliqué AVANT `overrides` : si un override "ID"
/// ou "SEQ" est aussi présent, il gagne (voir application dans main()).
#[derive(Deserialize, Debug, Default)]
struct HeaderOverride {
    /// Version (3 bits, bits 15-13 de ID) — nominal = 0
    version:      Option<u16>,
    /// Type (1 bit, bit 12 de ID) — 0=TM, 1=TC
    packet_type:  Option<u16>,
    /// Secondary Header Flag (1 bit, bit 11 de ID)
    sec_hdr_flag: Option<u16>,
    /// APID (11 bits, bits 10-0 de ID) — adresse de routage cFS
    apid:         Option<u16>,
    /// Sequence Flags (2 bits, bits 15-14 de SEQ) — nominal = 3 (0b11, complet)
    seq_flags:    Option<u16>,
    /// Sequence Count (14 bits, bits 13-0 de SEQ)
    seq_count:    Option<u16>,
}

#[derive(Deserialize, Debug)]
struct FieldOverride {
    /// Nom de l'arg tel qu'il apparaît dans catalogue_dump.json (ID, SEQ, LEN,
    /// FC, CHECKSUM, ou un argument applicatif du TC).
    name:  String,
    /// Valeur brute envoyée telle quelle (ex: "0xFF", "1234", "toto").
    value: String,
}

/// Applique les sous-champs de `header` sur l'arg nommé `arg_name`
/// (`ID` ou `SEQ`) en préservant les bits non concernés.
fn apply_header_bits(cmd: &mut input::CcsdsCommand, arg_name: &str, fields: &[(Option<u16>, u8, u8)]) {
    let Some(arg) = cmd.args.iter_mut().find(|a| a.name.eq_ignore_ascii_case(arg_name)) else {
        return;
    };
    let mut word = input::parse_uint(&arg.value).unwrap_or(0) as u16;
    let mut changed = false;
    for &(value, shift, width) in fields {
        if let Some(v) = value {
            word = input::set_bits(word, shift, width, v);
            changed = true;
        }
    }
    if changed {
        arg.value = format!("0x{word:04X}").into_bytes();
    }
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

    // Sous-champs du header CCSDS (granularité fine, comme les mutateurs 7-12) —
    // appliqués avant `overrides` pour que ceux-ci gagnent en cas de conflit.
    let h = &spec.header;
    apply_header_bits(&mut cmd, "ID", &[
        (h.version,      13, 3),
        (h.packet_type,  12, 1),
        (h.sec_hdr_flag, 11, 1),
        (h.apid,          0, 11),
    ]);
    apply_header_bits(&mut cmd, "SEQ", &[
        (h.seq_flags, 14, 2),
        (h.seq_count,  0, 14),
    ]);

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
