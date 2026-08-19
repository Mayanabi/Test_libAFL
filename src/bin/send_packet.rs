//! Envoi manuel d'un paquet CCSDS unique à NOS3, hors séquence et hors boucle
//! LibAFL — pour tester un paquet fait main (faux flags, valeurs précises...)
//! en dehors de la mutation automatique.
//!
//! Structure alignée sur le paquet CCSDS réel : [header] (header primaire,
//! 48 bits), [secondary_header] (FC/CHECKSUM), [[payload]] (user data field —
//! paramètres applicatifs du TC).
//!
//! Usage : cargo run --bin send_packet [-- chemin/vers/spec.toml]
//! (par défaut : one_shot.toml à la racine du projet)

use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;

use maya_libafl_poc::{catalogue, generator, input};
use input::CcsdsSequenceInput;

/// Noms d'args gérés par [header]/[secondary_header] — un [[payload]] qui
/// cible l'un de ces noms est ignoré avec un avertissement (utiliser la
/// section dédiée à la place, pas d'ambiguïté possible sur qui gagne).
const RESERVED_ARG_NAMES: &[&str] = &["ID", "SEQ", "LEN", "FC", "CHECKSUM"];

#[derive(Deserialize, Debug)]
struct OneShotSpec {
    /// Template de départ dans catalogue_dump.json (fournit port/target/args par défaut).
    tc_name: String,
    /// Header CCSDS primaire (48 bits : ID + SEQ), sous-champ par sous-champ —
    /// même granularité que les mutateurs 7-12 (VersionMutator, ApidMutator, ...).
    #[serde(default)]
    header: HeaderFields,
    /// Secondary header (convention cFS : Function Code + Checksum).
    #[serde(default)]
    secondary_header: SecondaryHeaderFields,
    /// User data field : paramètres applicatifs propres au TC (au-delà de
    /// ID/SEQ/LEN/FC/CHECKSUM).
    #[serde(default)]
    payload: Vec<PayloadField>,
    delay_min_ms: Option<u32>,
    delay_max_ms: Option<u32>,
}

/// Sous-champs du primary header CCSDS (48 bits, voir input.rs) — chacun
/// optionnel, seuls ceux présents dans le TOML sont modifiés, le reste vient
/// du template `tc_name`. C'est le SEUL moyen de toucher ID/SEQ (pas
/// d'override générique concurrent possible).
#[derive(Deserialize, Debug, Default)]
struct HeaderFields {
    /// Version (3 bits, bits 15-13 de ID) — nominal = 0
    version:      Option<u16>,
    /// Type (1 bit, bit 12 de ID) — 0=TM, 1=TC
    packet_type:  Option<u16>,
    /// Secondary Header Flag (1 bit, bit 11 de ID) — 0 = pas de secondary
    /// header, 1 = secondary header présent (FC/CHECKSUM ci-dessous)
    sec_hdr_flag: Option<u16>,
    /// APID (11 bits, bits 10-0 de ID) — adresse de routage cFS
    apid:         Option<u16>,
    /// Sequence Flags (2 bits, bits 15-14 de SEQ) — nominal = 3 (0b11, complet)
    seq_flags:    Option<u16>,
    /// Sequence Count (14 bits, bits 13-0 de SEQ)
    seq_count:    Option<u16>,
}

/// Secondary header CCSDS (convention cFS pour les commandes) : Function
/// Code + Checksum. N'a de sens que si header.sec_hdr_flag = 1.
#[derive(Deserialize, Debug, Default)]
struct SecondaryHeaderFields {
    fc:       Option<String>,
    checksum: Option<String>,
}

#[derive(Deserialize, Debug)]
struct PayloadField {
    /// Nom de l'arg applicatif tel qu'il apparaît dans catalogue_dump.json
    /// pour ce TC (ex: un paramètre spécifique, pas ID/SEQ/LEN/FC/CHECKSUM).
    name:  String,
    /// Valeur brute envoyée telle quelle (ex: "0xFF", "1234", "toto").
    value: String,
}

/// Applique les sous-champs de `header`/`secondary_header` sur l'arg nommé
/// `arg_name` en préservant les bits non concernés (pour ID/SEQ) ou en
/// remplaçant la valeur entière (pour FC/CHECKSUM).
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

fn set_arg(cmd: &mut input::CcsdsCommand, arg_name: &str, value: &str) {
    match cmd.args.iter_mut().find(|a| a.name.eq_ignore_ascii_case(arg_name)) {
        Some(arg) => arg.value = value.as_bytes().to_vec(),
        None => eprintln!("[send_packet] champ '{arg_name}' introuvable — ignoré"),
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

    // [header] : sous-champs de ID/SEQ, granularité fine (comme les mutateurs 7-12).
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

    // [secondary_header] : FC / CHECKSUM.
    if let Some(v) = &spec.secondary_header.fc       { set_arg(&mut cmd, "FC", v); }
    if let Some(v) = &spec.secondary_header.checksum { set_arg(&mut cmd, "CHECKSUM", v); }

    // [[payload]] : user data field, paramètres applicatifs uniquement —
    // ID/SEQ/LEN/FC/CHECKSUM ont déjà leur section dédiée ci-dessus.
    for p in &spec.payload {
        if RESERVED_ARG_NAMES.iter().any(|n| n.eq_ignore_ascii_case(&p.name)) {
            eprintln!(
                "[send_packet] '{}' se règle via [header]/[secondary_header], pas [[payload]] — ignoré",
                p.name
            );
            continue;
        }
        set_arg(&mut cmd, &p.name, &p.value);
    }

    let port = cmd.port;

    println!("[send_packet] {} → port {port}", spec.tc_name);
    let name_width = cmd.args.iter().map(|a| a.name.len()).max().unwrap_or(0);
    for arg in &cmd.args {
        println!(
            "  {:<name_width$} = {}",
            arg.name,
            String::from_utf8_lossy(&arg.value),
        );
    }
    println!();

    let seq  = CcsdsSequenceInput { commands: vec![cmd] };
    let json = serde_json::to_vec(&seq).expect("serialization should not fail");

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
    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let verdict = serde_json::from_str::<serde_json::Value>(raw_stdout.trim())
        .ok()
        .and_then(|v| v.get("verdict").and_then(|v| v.as_str()).map(str::to_owned))
        .unwrap_or_else(|| format!("(réponse inattendue: {})", raw_stdout.trim()));
    println!("[send_packet] verdict : {verdict}");
}
