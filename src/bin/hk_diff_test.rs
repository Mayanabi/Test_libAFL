//! Envoie une séquence connue à NOS3 en 3 phases (originale, mutée, puis
//! originale une seconde fois) et capture la télémétrie observée sur le bus
//! (logger Software Bus, /tmp/logids_p3.csv à l'intérieur du conteneur
//! nos-fsw) pendant chacune — aucune comparaison automatique, les 3 CSV
//! produits sont à consulter toi-même.
//!
//! NOS3 est redémarré (make stop && make launch) UNIQUEMENT entre la phase 1
//! et la phase 2 — pour que la séquence mutée (phase 2) parte d'un état
//! interne connu (compteurs HK à zéro), sans le bruit d'un éventuel run
//! précédent. Aucun redémarrage entre la phase 2 et la phase 3 : c'est ce
//! qui permet à un effet résiduel de la séquence mutée de persister jusqu'au
//! second envoi de la séquence originale, visible en comparant
//! hk_phase1_baseline.csv et hk_phase3_replay.csv.
//!
//! Usage : cargo run --bin hk_diff_test [-- chemin/vers/sequence.json]
//! (par défaut : state_sequences/NOVATEL_OEM615.json — voir le catalogue de
//! séquences d'état dans le dossier state_sequences/, aussi utilisé par
//! `cargo run -- --component ...` pour le fuzzing normal, voir README)
//!
//! Produit 3 fichiers CSV (toute la télémétrie — is_TC=0, pas seulement le
//! paquet HK périodique — des apps de la séquence, voir filter_app_telemetry
//! — observée pendant chaque phase) :
//!   hk_phase1_baseline.csv → pendant l'envoi de la séquence originale
//!   hk_phase2_mutated.csv  → pendant l'envoi de la séquence mutée
//!   hk_phase3_replay.csv   → pendant le second envoi de la séquence originale
//!
//! Les commandes (is_TC=1) et le trafic des apps qui n'ont rien à voir avec
//! la séquence testée sont exclus — mais toute la télémétrie DES APPS
//! CIBLÉES est gardée, pas seulement leur HK périodique : les réponses
//! ponctuelles comme DS_GET_FILE_INFO_CC (info fichier) ou
//! TBL_SEND_REGISTRY_CC (registre de table) apparaissent aussi dans les CSV
//! — et leurs events EVS aussi (CFE_ES_GetAppID() est appelé côté envoi dans
//! CFE_SB_TransmitMsg, donc un event publié via CFE_EVS_SendEvent() porte
//! l'AppId de l'app appelante, pas un AppId générique EVS — voir hk_appids).
//! Seuls les events des AUTRES apps (hors séquence testée) sont filtrés,
//! pas les events EVS en général. L'app source de chaque ligne est
//! identifiée par corrélation d'AppId avec son paquet HK (voir hk_appids)
//! plutôt que par une seconde table de MsgId à maintenir à la main.

use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use maya_libafl_poc::{
    config, nos3_control,
    input::{self, CcsdsSequenceInput, SelectedMutator},
};
use libafl::{mutators::Mutator, state::HasRand};
use libafl_bolts::{current_nanos, rands::StdRand};

const NOS_FSW_CONTAINER: &str = "sc01-nos-fsw";
const HK_LOG_PATH: &str = "/tmp/logids_p3.csv";
/// Intervalle entre deux vérifications de /tmp/logids_p3.csv.
const HK_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Temps max d'attente d'une ligne HK (MsgId attendu, is_TC=0) avant
/// d'abandonner et de capturer ce qu'on a — la cadence de publication HK
/// varie selon l'app, donc on attend un vrai signal plutôt qu'un délai fixe.
const HK_MAX_WAIT: Duration = Duration::from_secs(20);

/// État minimal pour pouvoir appeler un Mutator (qui n'a besoin que de
/// HasRand) sans monter tout un StdState de fuzzing (corpus/feedback/...).
struct MiniState {
    rand: StdRand,
}
impl HasRand for MiniState {
    type Rand = StdRand;
    fn rand(&self) -> &StdRand {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut StdRand {
        &mut self.rand
    }
}

/// Nombre de lignes actuellement dans /tmp/logids_p3.csv à l'intérieur du
/// conteneur nos-fsw (0 si le fichier n'existe pas encore).
fn hk_line_count() -> usize {
    let output = Command::new("docker")
        .args(["exec", NOS_FSW_CONTAINER, "wc", "-l", HK_LOG_PATH])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0),
        _ => 0,
    }
}

/// Récupère les lignes de /tmp/logids_p3.csv à partir de `start` (0-indexé,
/// exclut l'en-tête qui est à la ligne 1).
fn hk_lines_since(start: usize) -> Vec<String> {
    let output = Command::new("docker")
        .args(["exec", NOS_FSW_CONTAINER, "tail", "-n", "+2", HK_LOG_PATH])
        .output();
    let Ok(out) = output else { return vec![] };
    if !out.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(start.saturating_sub(1))
        .map(str::to_owned)
        .collect()
}

/// Table (MsgId commande → MsgId HK) extraite des headers *_msgids.h du
/// dépôt NOS3 (source de vérité, pas une heuristique) — un par app présente
/// dans catalogue_dump.json. Voir par ex.
/// components/novatel_oem615/fsw/cfs/platform_inc/novatel_oem615_msgids.h
/// (NOVATEL_OEM615_CMD_MID / NOVATEL_OEM615_HK_TLM_MID) et l'équivalent pour
/// chaque autre app dans fsw/apps/*/fsw/*inc/ et components/*/fsw/cfs/platform_inc/.
///
/// Attention : ce n'est PAS un simple "bit 12 à 0" — 8 apps sur 30 ont un HK
/// MsgId qui ne dérive pas directement du MsgId de commande (ex: CF
/// 0x18B3→0x08B0, DS 0x18BB→0x08B8, SC 0x18A9→0x08AA, SCH 0x1895→0x0897,
/// LC 0x18A4→0x08A7, ES 0x1806→0x0800, FM 0x188C→0x088A, SBN 0x18DA→0x08DC).
const CMD_TO_HK_MID: &[(u16, u16)] = &[
    (0x18C8, 0x08C8), // ARDUCAM (CAM)
    (0x18B3, 0x08B0), // CF
    (0x1884, 0x0884), // CI
    (0x18BB, 0x08B8), // DS
    (0x1806, 0x0800), // ES
    (0x1801, 0x0801), // EVS
    (0x188C, 0x088A), // FM
    (0x1940, 0x0940), // GENERIC_ADCS
    (0x1910, 0x0910), // GENERIC_CSS
    (0x191A, 0x091A), // GENERIC_EPS
    (0x1920, 0x0920), // GENERIC_FSS
    (0x1925, 0x0925), // GENERIC_IMU
    (0x192A, 0x092A), // GENERIC_MAG
    (0x1930, 0x0930), // GENERIC_RADIO
    (0x1992, 0x0993), // GENERIC_REACTION_WHEEL
    (0x1935, 0x0935), // GENERIC_STAR_TRACKER
    (0x18EA, 0x08EA), // GENERIC_THRUSTER
    (0x193A, 0x093A), // GENERIC_TORQUER
    (0x18A4, 0x08A7), // LC
    (0x18F8, 0x08F8), // MGR
    (0x1870, 0x0870), // NOVATEL_OEM615
    (0x18FA, 0x08FA), // SAMPLE
    (0x1803, 0x0803), // SB
    (0x18DA, 0x08DC), // SBN
    (0x18A9, 0x08AA), // SC
    (0x1895, 0x0897), // SCH
    (0x18FC, 0x08FC), // SYN
    (0x1804, 0x0804), // TBL
    (0x1805, 0x0805), // TIME
    (0x1880, 0x0880), // TO
    (0x18E8, 0x08E8), // TO_LAB
];

/// Résout le MsgId HK pour un MsgId de commande. Retombe sur l'ancienne
/// heuristique (bit 12 à 0) avec un avertissement si le MsgId n'est pas dans
/// la table — n'arrive que pour un nouvel app ajouté à NOS3 après coup et pas
/// encore répertorié ci-dessus.
fn hk_mid_for_cmd(cmd_mid: u16) -> u16 {
    match CMD_TO_HK_MID.iter().find(|(cmd, _)| *cmd == cmd_mid) {
        Some((_, hk)) => *hk,
        None => {
            eprintln!(
                "[hk_diff_test] ⚠ MsgId 0x{cmd_mid:04X} absent de CMD_TO_HK_MID \
                 (app non répertoriée) — repli sur l'heuristique bit12=0, à vérifier"
            );
            cmd_mid & !0x1000u16
        }
    }
}

/// MsgId HK attendu pour chaque commande de la séquence, via CMD_TO_HK_MID.
fn expected_hk_msgids(seq: &CcsdsSequenceInput) -> Vec<String> {
    seq.commands
        .iter()
        .filter_map(|cmd| cmd.args.iter().find(|a| a.name.eq_ignore_ascii_case("ID")))
        .filter_map(|id_arg| input::parse_uint(&id_arg.value))
        .map(|id| format!("{:04x}", hk_mid_for_cmd(id as u16)))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

/// AppId (colonne 6 du CSV, App ID cFE ES du process) des apps ciblées par
/// la séquence — déduit par corrélation avec leur paquet HK périodique
/// (is_TC=0, MsgId parmi expected_hk_msgids) plutôt que par une table
/// séparée : dans cFS, un app = un process = un AppId unique, partagé par
/// tous les messages qu'il émet (HK et le reste), donc l'AppId vu sur son
/// paquet HK identifie aussi bien sa télémétrie ponctuelle.
fn hk_appids(lines: &[String], expected_hk_msgids: &[String]) -> HashSet<String> {
    lines
        .iter()
        .filter_map(|line| parse_row(line))
        .filter(|r| r.is_tc == "0" && expected_hk_msgids.iter().any(|m| m == r.msgid))
        .map(|r| r.appid.to_string())
        .collect()
}

/// Ne garde que la télémétrie (is_TC=0) émise par les AppId identifiés via
/// hk_appids — c'est-à-dire toute la télémétrie des apps ciblées par la
/// séquence : HK périodique, réponses ponctuelles (DS_GET_FILE_INFO_CC,
/// TBL_SEND_REGISTRY_CC, ...) ET leurs events EVS (même AppId que le reste
/// de l'app, voir le commentaire en tête de fichier). Exclut les commandes
/// (is_TC=1) et tout le trafic — event EVS compris — des apps qui n'ont rien
/// à voir avec la séquence testée.
fn filter_app_telemetry(lines: &[String], target_appids: &HashSet<String>) -> Vec<String> {
    lines
        .iter()
        .filter(|line| {
            parse_row(line).is_some_and(|r| r.is_tc == "0" && target_appids.contains(r.appid))
        })
        .cloned()
        .collect()
}

/// Une ligne CSV a le format simtime,realtime,MsgId,FC,is_TC,AppId,... —
/// retourne (MsgId, is_TC) si la ligne est bien formée.
fn parse_msgid_is_tc(line: &str) -> Option<(&str, &str)> {
    let mut cols = line.split(',');
    let _simtime = cols.next()?;
    let _realtime = cols.next()?;
    let msgid = cols.next()?;
    let _fc = cols.next()?;
    let is_tc = cols.next()?;
    Some((msgid, is_tc))
}

/// Une ligne du CSV brut de bus.c, décomposée pour affichage — mêmes 10
/// colonnes que update_Log_P3() dans fsw/cfe/modules/sb/fsw/src/bus.c
/// (simtime,realtime,MsgId,FC,is_TC,AppId,TaskName,AttackTag,is_allowed,
/// packet), rien n'est supprimé — seul le hex du paquet est tronqué à
/// l'affichage (voir PACKET_HEX_PREVIEW_LEN).
struct HkRow<'a> {
    simtime: &'a str,
    realtime: &'a str,
    msgid: &'a str,
    fc: &'a str,
    is_tc: &'a str,
    appid: &'a str,
    task_name: &'a str,
    attack_tag: &'a str,
    is_allowed: &'a str,
    packet_hex: &'a str,
}

fn parse_row(line: &str) -> Option<HkRow<'_>> {
    let mut c = line.split(',');
    let simtime = c.next()?;
    let realtime = c.next()?;
    let msgid = c.next()?;
    let fc = c.next()?;
    let is_tc = c.next()?;
    let appid = c.next()?;
    let task_name = c.next()?;
    let attack_tag = c.next()?;
    let is_allowed = c.next()?;
    let packet_hex = c.next().unwrap_or("");
    Some(HkRow {
        simtime, realtime, msgid, fc, is_tc, appid, task_name, attack_tag, is_allowed, packet_hex,
    })
}

/// Longueur max du hex du paquet affichée en clair avant troncature (le
/// reste est juste compté en octets) — sinon une seule ligne peut faire
/// jusqu'à ~1400 caractères (paquets EVS avec texte d'event embarqué).
const PACKET_HEX_PREVIEW_LEN: usize = 40;

/// Largeurs de colonnes fixes (tout ce qui n'est pas dimensionné sur le
/// contenu, cf app_width plus bas).
const COL_SIMTIME: usize = 12;
const COL_TEMPS: usize = 10;
const COL_MSGID: usize = 6;
const COL_FC: usize = 4;
const COL_TYPE: usize = 4;
const COL_APPID: usize = 9;
const COL_ATTACK: usize = 6;
const COL_ALLOWED: usize = 10;

/// Tronque le hex d'un paquet à PACKET_HEX_PREVIEW_LEN caractères, avec le
/// nombre d'octets omis affiché à côté — utilisé par format_hk_table pour
/// qu'une ligne ne dépasse pas ~200 caractères.
fn preview_hex(hex: &str) -> String {
    let total = hex.len();
    let n = total.min(PACKET_HEX_PREVIEW_LEN);
    let preview = &hex[..n];
    let remaining = (total - n) / 2;
    if remaining > 0 {
        format!("{preview}... (+{remaining} octets)")
    } else {
        preview.to_string()
    }
}

/// Reformate les lignes brutes du CSV en tableau aligné et lisible — mêmes
/// 10 colonnes que le CSV brut de bus.c (rien n'est supprimé), juste le hex
/// du paquet tronqué avec le nombre d'octets omis affiché à côté, au lieu
/// d'une ligne CSV de plusieurs centaines de caractères.
fn format_hk_table(lines: &[String]) -> String {
    let rows: Vec<HkRow> = lines.iter().filter_map(|l| parse_row(l)).collect();
    if rows.is_empty() {
        return "(aucune ligne)".to_string();
    }

    let app_width = rows.iter().map(|r| r.task_name.len()).max().unwrap_or(3).max(3);

    let mut out = String::new();
    out.push_str(&format!(
        "{:<COL_SIMTIME$} {:<COL_TEMPS$} {:<COL_MSGID$} {:<COL_FC$} {:<COL_TYPE$} {:<COL_APPID$} {:<app_width$} {:<COL_ATTACK$} {:<COL_ALLOWED$} {}\n",
        "simtime", "Temps(s)", "MsgId", "FC", "Type", "AppId", "App", "Attack", "is_allowed",
        "Paquet (début hex, octets restants entre parenthèses)"
    ));
    let sep_len = COL_SIMTIME + COL_TEMPS + COL_MSGID + COL_FC + COL_TYPE + COL_APPID
        + app_width + COL_ATTACK + COL_ALLOWED + 9 /* espaces entre colonnes */ + 55;
    out.push_str(&"-".repeat(sep_len));
    out.push('\n');

    for r in &rows {
        let kind = if r.is_tc == "1" { "CMD" } else { "TLM" };
        let fc = if r.fc == "-1" { "-".to_string() } else { r.fc.to_string() };
        let packet_display = preview_hex(r.packet_hex);

        out.push_str(&format!(
            "{:<COL_SIMTIME$} {:<COL_TEMPS$} {:<COL_MSGID$} {:<COL_FC$} {:<COL_TYPE$} {:<COL_APPID$} {:<app_width$} {:<COL_ATTACK$} {:<COL_ALLOWED$} {}\n",
            r.simtime, r.realtime, r.msgid, fc, kind, r.appid, r.task_name, r.attack_tag, r.is_allowed, packet_display
        ));
    }

    out
}

/// Poll /tmp/logids_p3.csv jusqu'à voir une ligne HK (is_TC=0) avec un des
/// MsgId attendus, ou jusqu'à HK_MAX_WAIT. Retourne (lignes capturées, HK
/// attendue effectivement vue ou pas).
fn wait_for_hk(before: usize, expected_msgids: &[String]) -> (Vec<String>, bool) {
    let deadline = Instant::now() + HK_MAX_WAIT;
    loop {
        let lines = hk_lines_since(before);
        let found = lines.iter().any(|line| {
            parse_msgid_is_tc(line)
                .is_some_and(|(msgid, is_tc)| is_tc == "0" && expected_msgids.iter().any(|m| m == msgid))
        });
        if found || Instant::now() >= deadline {
            return (lines, found);
        }
        std::thread::sleep(HK_POLL_INTERVAL);
    }
}

/// Envoie une séquence à wrapper.py et affiche le verdict — même mécanisme
/// que send_packet, mais pour une séquence complète (potentiellement
/// plusieurs commandes) au lieu d'un seul paquet.
fn send_sequence(seq: &CcsdsSequenceInput, label: &str) {
    let json = serde_json::to_vec(seq).expect("serialization should not fail");

    let mut child = Command::new("python3")
        .arg("wrapper.py")
        .env("FUZZ_MODE", "normal")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("impossible de lancer wrapper.py");

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(&json)
        .expect("écriture stdin échouée");

    let output = child.wait_with_output().expect("échec de wrapper.py");
    let raw = String::from_utf8_lossy(&output.stdout);
    let verdict = serde_json::from_str::<serde_json::Value>(raw.trim())
        .ok()
        .and_then(|v| v.get("verdict").and_then(|v| v.as_str()).map(str::to_owned))
        .unwrap_or_else(|| format!("(réponse inattendue: {})", raw.trim()));
    println!("[hk_diff_test] {label} → verdict : {verdict}");
}

/// Envoie la séquence, attend qu'un cycle HK des apps ciblées apparaisse
/// (plutôt qu'un délai fixe, voir wait_for_hk), déduit l'AppId de ces apps
/// par corrélation avec ce paquet HK (hk_appids), puis garde toute leur
/// télémétrie (filter_app_telemetry) captée sur le bus pendant cette fenêtre
/// — le fichier écrit couvre donc HK + réponses ponctuelles + events EVS des
/// apps de la séquence, sans le bruit des autres (commandes, scheduler, apps
/// hors séquence).
fn run_phase(seq: &CcsdsSequenceInput, label: &str, out_file: &str) {
    let before = hk_line_count();
    send_sequence(seq, label);

    let expected = expected_hk_msgids(seq);
    let (new_lines, found) = wait_for_hk(before, &expected);
    let target_appids = hk_appids(&new_lines, &expected);
    let tlm_lines = filter_app_telemetry(&new_lines, &target_appids);

    std::fs::write(out_file, format_hk_table(&tlm_lines)).expect("écriture du fichier HK échouée");
    if found {
        println!(
            "[hk_diff_test] HK attendue vue — {} ligne(s) télémétrie capturée(s) (sur {} lignes de trafic bus total) → {out_file}",
            tlm_lines.len(), new_lines.len()
        );
    } else {
        println!(
            "[hk_diff_test] ⚠ timeout ({}s) sans voir la HK attendue (MsgId {:?}) — {} ligne(s) télémétrie capturée(s) quand même (sur {} lignes de trafic bus total) → {out_file}",
            HK_MAX_WAIT.as_secs(), expected, tlm_lines.len(), new_lines.len()
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).map(String::as_str).unwrap_or("state_sequences/NOVATEL_OEM615.json");

    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Impossible de lire {path}: {e}"));
    let original: CcsdsSequenceInput =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("JSON invalide dans {path}: {e}"));

    let cfg = config::load("fuzz_config.toml");
    let mut mutator = SelectedMutator::new(cfg.mutators.clone());
    let mut state = MiniState { rand: StdRand::with_seed(current_nanos()) };

    println!("[hk_diff_test] === Phase 1 : séquence originale (baseline) ===");
    run_phase(&original, "baseline", "hk_phase1_baseline.csv");

    println!("[hk_diff_test] Redémarrage NOS3 avant la phase 2 (repartir d'un état propre)...");
    nos3_control::restart_nos3();

    println!("[hk_diff_test] === Phase 2 : séquence mutée ===");
    let mut mutated = original.clone();
    mutator
        .mutate(&mut state, &mut mutated)
        .expect("la mutation a échoué");
    run_phase(&mutated, "mutée", "hk_phase2_mutated.csv");

    println!("[hk_diff_test] === Phase 3 : re-rejeu de la séquence originale ===");
    run_phase(&original, "replay original", "hk_phase3_replay.csv");

    println!();
    println!("[hk_diff_test] Terminé. Détails dans hk_phase1_baseline.csv / hk_phase2_mutated.csv / hk_phase3_replay.csv");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une ligne courte doit passer intégralement (pas de troncature quand
    /// ce n'est pas nécessaire), une ligne longue (paquet EVS avec texte
    /// embarqué, ~1300+ caractères hex en pratique) doit être tronquée avec
    /// le nombre d'octets omis affiché — sinon le fichier redevient
    /// illisible exactement comme le CSV brut qu'on remplace.
    #[test]
    fn format_hk_table_truncates_long_packets_only() {
        let short = "2505400000,259.250126,1870,0,1,1114121,CI_LAB_APP,0,-1,1870c00000010000".to_string();
        let long_hex = "ab".repeat(700); // 1400 caractères hex
        let long = format!("2719200000,280.737336,0941,-1,0,1114128,ADCS,0,-1,{long_hex}");

        let table = format_hk_table(&[short, long]);

        assert!(table.contains("1870c00000010000"), "ligne courte doit rester intacte:\n{table}");
        assert!(table.contains("(+"), "ligne longue doit être annotée avec les octets omis:\n{table}");
        assert!(
            table.lines().all(|l| l.len() < 200),
            "aucune ligne du tableau ne doit dépasser ~200 caractères:\n{table}"
        );
    }

    /// hk_appids doit déduire l'AppId (colonne 6) à partir du paquet HK
    /// (is_TC=0, MsgId attendu) — pas des commandes ni d'un MsgId hors
    /// liste — pour ensuite pouvoir élargir le filtre à toute la télémétrie
    /// de cet AppId.
    #[test]
    fn hk_appids_correlates_appid_from_hk_packet_only() {
        let expected = vec!["0870".to_string()];
        let lines = vec![
            "2504500000,259.1,1870,0,1,111,NAV,0,-1,1870c00000010000".to_string(), // commande NAV (is_TC=1)
            "2504500000,259.2,0808,-1,0,112,TO_LAB_APP,0,-1,4e4f56415400".to_string(), // event EVS, MsgId hors liste
            "2504500000,259.3,0870,-1,0,111,NAV,0,-1,0870c0000001aabbcc".to_string(), // vraie HK NAV, AppId=111
        ];

        let appids = hk_appids(&lines, &expected);

        assert_eq!(appids.len(), 1, "attendu un seul AppId déduit:\n{appids:?}");
        assert!(appids.contains("111"));
    }

    /// filter_app_telemetry doit exclure les commandes (is_TC=1) et le
    /// trafic d'un AppId non ciblé, mais garder TOUTE la télémétrie de
    /// l'AppId ciblé — pas seulement son paquet HK (ex: une réponse
    /// ponctuelle sur un MsgId différent, ici 0871).
    #[test]
    fn filter_app_telemetry_keeps_all_target_appid_tlm() {
        let target: HashSet<String> = ["111".to_string()].into_iter().collect();
        let lines = vec![
            "2504500000,259.1,1870,0,1,111,NAV,0,-1,1870c00000010000".to_string(), // commande NAV (is_TC=1) — exclue
            "2504500000,259.2,0808,-1,0,112,TO_LAB_APP,0,-1,4e4f56415400".to_string(), // event EVS, AppId non ciblé — exclue
            "2504500000,259.3,0870,-1,0,111,NAV,0,-1,0870c0000001aabbcc".to_string(), // HK NAV — gardée
            "2504500000,259.4,0871,-1,0,111,NAV,0,-1,0871c000000102".to_string(), // réponse ponctuelle NAV, MsgId différent — gardée
        ];

        let filtered = filter_app_telemetry(&lines, &target);

        assert_eq!(filtered.len(), 2, "attendu HK + réponse ponctuelle gardées:\n{filtered:?}");
        assert!(filtered.iter().any(|l| l.contains("0870c0000001aabbcc")));
        assert!(filtered.iter().any(|l| l.contains("0871c000000102")));
    }
}
