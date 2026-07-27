use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{HasTargetBytes, Input},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error, SerdeAny,
};
use libafl_bolts::{rands::Rand, Named};
use serde::{Deserialize, Serialize};
use libafl_bolts::ownedref::OwnedSlice;

// ─── Types de données CCSDS ──────────────────────────────────────────────────

/// Type d'argument tel qu'attendu par CmdSender.py (valeur sérialisée en JSON
/// en MAJUSCULES pour correspondre à la convention du catalogue NOS3).
#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub enum ArgType {
    #[serde(rename = "UINT")]   UInt,
    #[serde(rename = "INT")]    Int,
    #[serde(rename = "FLOAT")]  Float,
    #[serde(rename = "STRING")] StringT,  // "String" est réservé en Rust
    #[serde(rename = "BLOCK")]  Block,
}

/// Endianness optionnel — None = défaut CCSDS (big-endian), sérialisé absent
/// de l'objet JSON (skip_serializing_if = None) pour correspondre à CmdSender.
#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub enum Endianness {
    #[serde(rename = "BIG")]    Big,
    #[serde(rename = "LITTLE")] Little,
}

/// Un argument d'une commande CCSDS.
///
/// `value` est stocké en bytes ASCII (ex: b"0x1806") plutôt qu'en String, pour
/// permettre les mutations havoc brutes sans risquer de produire une String Rust
/// non-UTF-8. La conversion en String n'a lieu qu'à la sérialisation JSON finale,
/// via `value_to_str`. Les mutations qui produisent des bytes non-ASCII sont
/// intentionnelles pour que le fuzzer teste précisément comment NOS3 réagit à des
/// valeurs malformées.
#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub struct CcsdsArg {
    pub name:       String,
    pub arg_type:   ArgType,
    pub size_bits:  u16,
    #[serde(
        serialize_with   = "value_to_str",
        deserialize_with = "value_from_str"
    )]
    pub value:      Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
}

fn value_to_str<S: serde::Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    // from_utf8_lossy : pour les bytes qui sont non-UTF-8 ça les remplace par : U+FFFD
    // qui est un caractère de remplacement 
    // Le wrapper Python recevra du texte légèrement malformé — comportement
    // voulu pour un test de robustesse.
    s.serialize_str(&String::from_utf8_lossy(v))
}

fn value_from_str<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    Ok(String::deserialize(d)?.into_bytes())
}

/// Une commande TC CCSDS complète, avec ses métadonnées de séquencement.
///
/// Convention d'index :
///   args[0] = ID (APID)   args[1] = SEQ   args[2] = LEN
///   args[3] = FC          args[4] = CHECKSUM
///   args[5..] = paramètres applicatifs
///
/// Cette convention est celle de nos3_adapter.py/CmdSender.py et doit être
/// préservée pour que la sérialisation JSON soit interprétable par wrapper.py.
#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub struct CcsdsCommand {
    pub step:         i32,
    pub tc_name:      String,
    pub fuzz:         bool,
    pub mandatory:    bool,
    pub delay_min_ms: u32,
    pub delay_max_ms: u32,
    pub args:         Vec<CcsdsArg>,
    pub target:       String,
    pub mutation:     String,
    pub replay:       bool,
}

/// Input LibAFL : séquence ordonnée de commandes CCSDS.

#[derive(Serialize, Deserialize, Debug, Clone, Hash, SerdeAny)]
pub struct CcsdsSequenceInput {
    pub commands: Vec<CcsdsCommand>,
}

impl Input for CcsdsSequenceInput {}

/// Sérialisée en JSON avant d'être passée à wrapper.py via stdin
impl HasTargetBytes for CcsdsSequenceInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        OwnedSlice::from(serde_json::to_vec(self).expect("serialization should not fail"))
    }
}

// ─── Mutateurs ───────────────────────────────────────────────────────────────

// ─── Helper partagé ──────────────────────────────────────────────────────────

/// Parse une valeur ASCII décimale ou hexadécimale vers u64.
/// Retourne None si la valeur est corrompue (non-UTF8, format invalide).
fn parse_uint(bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Lit un sous-champ de `width` bits à la position `shift` dans un mot 16 bits.
fn extract_bits(word: u16, shift: u8, width: u8) -> u16 {
    let mask = (1u16 << width) - 1;
    (word >> shift) & mask
}

/// Remplace un sous-champ de `width` bits à la position `shift` dans un mot 16
/// bits, en conservant les autres bits inchangés.
fn set_bits(word: u16, shift: u8, width: u8, new_val: u16) -> u16 {
    let mask = (1u16 << width) - 1;
    (word & !(mask << shift)) | ((new_val & mask) << shift)
}

// Tables de valeurs intéressantes par taille de champ.

const INTERESTING_U8:  &[u64] = &[0, 1, 0x7F, 0x80, 0xFE, 0xFF];
const INTERESTING_U16: &[u64] = &[0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF];
const INTERESTING_U32: &[u64] = &[0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFE, 0xFFFF_FFFF];

fn interesting_ints(size_bits: u16) -> &'static [u64] {
    match size_bits {
        ..=8  => INTERESTING_U8,
        ..=16 => INTERESTING_U16,
        _     => INTERESTING_U32,
    }
}

// ─── 1. ArgValueMutator (havoc byte-level — utile pour STRING/BLOCK) ─────────

/// Mutations havoc brutes sur les bytes ASCII de la `value`.

pub struct ArgValueMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for ArgValueMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        // Construire la liste des target (ci, ai) dans les commandes fuzzables
        let targets: Vec<(usize, usize)> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz)
            .flat_map(|(ci, cmd)| (0..cmd.args.len()).map(move |ai| (ci, ai)))
            .collect();

        if targets.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Récupérer tous les nombres aléatoires avant d'emprunter `input`
        let rng      = state.rand_mut();
        let (ci, ai) = targets[rng.next() as usize % targets.len()];
        let mutation = (rng.next() % 5) as u8;
        let r1       = rng.next();
        let r2       = rng.next();

        let value = &mut input.commands[ci].args[ai].value;
        if value.is_empty() {
            value.push(b'0');
            return Ok(MutationResult::Mutated);
        }
        let len = value.len();

        match mutation {
            0 => // Bit flip
                value[(r1 as usize) % len] ^= 1u8 << (r2 % 8) as u8,
            1 => // Byte aléatoire (peut produire du non-ASCII — intentionnel)
                value[(r1 as usize) % len] = r2 as u8,
            2 => // Insérer un byte ASCII imprimable
                value.insert((r1 as usize) % (len + 1), 0x20u8.wrapping_add((r2 as u8) % 0x60)),
            3 if len > 1 => // Supprimer un byte
                { value.remove((r1 as usize) % len); }
            _ => { // Copier un byte (équivalent BytesCopyMutator)
                let b = value[(r1 as usize) % len];
                value[(r2 as usize) % len] = b;
            }
        }

        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}

impl Named for ArgValueMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("ArgValueMutator") }
}

// ─── 2. FcWalkMutator ────────────────────────────────────────────────────────

/// Cible spécifiquement le champ FC (args[3], convention nos3_adapter.py) et
/// le fait varier de façon structurée. Chaque valeur de FC = handler différent
/// dans cFS → c'est le levier le plus direct pour découvrir de nouveaux
/// comportements sans changer d'app.
///
/// Stratégie : 1/3 sauts aléatoires (0-255), 2/3 incréments/décréments de ±1..16
/// pour explorer le voisinage du FC courant.
pub struct FcWalkMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for FcWalkMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let fuzz_cmds: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 3)
            .map(|(ci, _)| ci)
            .collect();
        if fuzz_cmds.is_empty() { return Ok(MutationResult::Skipped); }

        let rng  = state.rand_mut();
        let ci   = fuzz_cmds[rng.next() as usize % fuzz_cmds.len()];
        let r1   = rng.next();
        let r2   = rng.next();

        let fc_arg  = &mut input.commands[ci].args[3];
        let current = parse_uint(&fc_arg.value).unwrap_or(0);

        let new_fc = if r1 % 3 == 0 {
            r2 % 256                                         // saut aléatoire complet
        } else {
            let delta = r2 % 16 + 1;
            if r1 % 2 == 0 { current.wrapping_add(delta) % 256 }
            else            { current.saturating_sub(delta) }
        };
        fc_arg.value = format!("0x{new_fc:02X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for FcWalkMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("FcWalkMutator") }
}

// ─── 3. IntBoundaryMutator ───────────────────────────────────────────────────

/// Génère des valeurs aux frontières pour les args UINT/INT en respectant la
/// taille déclarée (size_bits). Beaucoup plus efficace que les bit-flips aléatoires
/// pour trouver des overflows, underflows et comportements off-by-one dans cFS.
pub struct IntBoundaryMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for IntBoundaryMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<(usize, usize)> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz)
            .flat_map(|(ci, cmd)| {
                cmd.args.iter().enumerate()
                    .filter(|(_, a)| matches!(a.arg_type, ArgType::UInt | ArgType::Int))
                    .map(move |(ai, _)| (ci, ai))
            })
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng      = state.rand_mut();
        let (ci, ai) = targets[rng.next() as usize % targets.len()];
        let r        = rng.next();

        let arg   = &mut input.commands[ci].args[ai];
        let table = interesting_ints(arg.size_bits);
        arg.value = table[r as usize % table.len()].to_string().into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for IntBoundaryMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("IntBoundaryMutator") }
}

// ─── 4. StringSpecialMutator ─────────────────────────────────────────────────

/// Injecte des chaînes connues pour casser le pipeline JSON → wrapper.py →
/// CmdSender.py → cFS (C) dans les args de type STRING : format strings,
/// path traversal, null byte, guillemet/backslash non échappés, chaîne longue.
pub struct StringSpecialMutator;

const STRING_SPECIAL: &[&str] = &[
    "",
    "%s%s%s%s",
    "%n",
    "../../etc/passwd",
    "'",
    "\"",
    "\\",
    "\0",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
];

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for StringSpecialMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<(usize, usize)> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz)
            .flat_map(|(ci, cmd)| {
                cmd.args.iter().enumerate()
                    .filter(|(_, a)| matches!(a.arg_type, ArgType::StringT))
                    .map(move |(ai, _)| (ci, ai))
            })
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng      = state.rand_mut();
        let (ci, ai) = targets[rng.next() as usize % targets.len()];
        let r        = rng.next();

        input.commands[ci].args[ai].value =
            STRING_SPECIAL[r as usize % STRING_SPECIAL.len()].as_bytes().to_vec();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for StringSpecialMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("StringSpecialMutator") }
}

// ─── 5. CommandReorderMutator ────────────────────────────────────────────────

/// Échange deux commandes aléatoires dans la séquence.
/// En mode cross_app, teste directement si l'ORDRE d'envoi influence
/// le comportement de NOS3 (état partagé entre apps, dépendances temporelles).
pub struct CommandReorderMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for CommandReorderMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let n = input.commands.len();
        if n < 2 { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let i   = rng.next() as usize % n;
        let j   = rng.next() as usize % n;
        if i == j { return Ok(MutationResult::Skipped); }

        input.commands.swap(i, j);
        // Resynchroniser les step numbers après le swap
        for (step, cmd) in input.commands.iter_mut().enumerate() {
            cmd.step = step as i32 + 1;
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for CommandReorderMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("CommandReorderMutator") }
}

// ─── 6. DelayMutator ─────────────────────────────────────────────────────────

/// Explore l'impact des délais inter-commandes sur le comportement de NOS3.
pub struct DelayMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for DelayMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        if input.commands.is_empty() { return Ok(MutationResult::Skipped); }

        let rng   = state.rand_mut();
        let ci    = rng.next() as usize % input.commands.len();
        let field = rng.next() % 2;
        let delta = (rng.next() % 100) as u32;

        let cmd = &mut input.commands[ci];
        if field == 0 {
            cmd.delay_min_ms = cmd.delay_min_ms.wrapping_add(delta);
        } else {
            cmd.delay_max_ms = cmd.delay_max_ms.wrapping_add(delta);
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for DelayMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("DelayMutator") }
}

// ─── Primary Header CCSDS (mutateurs 7 à 12) ─────────────────────────────────
//
// Le primary header CCSDS fait 48 bits (standard CCSDS 133.0-B, "Space Packet
// Protocol"), découpés en 3 mots de 16 bits. Les deux premiers sont déjà
// présents dans chaque `CcsdsCommand`, mais traités jusqu'ici comme des UINT
// opaques par les autres mutateurs (ex: IntBoundaryMutator) :
//
//   args[0] = "ID"  (Packet Identification)
//     bits 15-13 : Version           (3 bits)
//     bit  12    : Type              (1 bit — 0=TM, 1=TC)
//     bit  11    : Secondary Header Flag (1 bit)
//     bits 10-0  : APID              (11 bits — adresse de routage cFS)
//
//   args[1] = "SEQ" (Packet Sequence Control)
//     bits 15-14 : Sequence Flags    (2 bits — 11=complet, 01/00/10=segmenté)
//     bits 13-0  : Sequence Count    (14 bits — compteur anti-perte, wrap 0x3FFF→0)
//
// Les 6 mutateurs ci-dessous ciblent chacun un seul sous-champ, en lisant/
// écrivant args[0] ou args[1] via extract_bits/set_bits plutôt que de traiter
// le mot 16 bits comme une valeur opaque.

// ─── 7. VersionMutator ───────────────────────────────────────────────────────

/// Tire une valeur aléatoire dans 0-7 pour le champ Version (3 bits) de l'ID.
/// Le nominal observé dans le catalogue NOS3 est 0 ; les autres valeurs testent
/// si cFS rejette proprement une version de protocole qu'il ne reconnaît pas.
pub struct VersionMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for VersionMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];
        let r   = rng.next();

        let id_arg  = &mut input.commands[ci].args[0];
        let id      = parse_uint(&id_arg.value).unwrap_or(0) as u16;
        let new_id  = set_bits(id, 13, 3, (r % 8) as u16);
        id_arg.value = format!("0x{new_id:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for VersionMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("VersionMutator") }
}

// ─── 8. PacketTypeMutator ────────────────────────────────────────────────────

/// Flip le bit Type (bit 12 de l'ID) entre TC (1) et TM (0). Les séquences
/// fuzzées sont des télécommandes ; forcer TM teste la réaction de cFS à un
/// type de paquet incohérent avec le contexte d'envoi.
pub struct PacketTypeMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for PacketTypeMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];

        let id_arg   = &mut input.commands[ci].args[0];
        let id       = parse_uint(&id_arg.value).unwrap_or(0) as u16;
        let cur_type = extract_bits(id, 12, 1);
        let new_id   = set_bits(id, 12, 1, cur_type ^ 1);
        id_arg.value = format!("0x{new_id:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for PacketTypeMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("PacketTypeMutator") }
}

// ─── 9. SecHdrFlagMutator ────────────────────────────────────────────────────

/// Flip le bit Secondary Header Flag (bit 11 de l'ID). Le mettre en désaccord
/// avec le contenu réel du paquet (présence/absence d'un secondary header)
/// crée une incohérence structurelle : cFS peut lire le payload avec un
/// décalage d'offset erroné.
pub struct SecHdrFlagMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for SecHdrFlagMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];

        let id_arg  = &mut input.commands[ci].args[0];
        let id      = parse_uint(&id_arg.value).unwrap_or(0) as u16;
        let cur_flag = extract_bits(id, 11, 1);
        let new_id  = set_bits(id, 11, 1, cur_flag ^ 1);
        id_arg.value = format!("0x{new_id:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for SecHdrFlagMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("SecHdrFlagMutator") }
}

// ─── 10. ApidMutator ─────────────────────────────────────────────────────────

const APID_BOUNDARIES: &[u16] = &[0, 1, 0x400, 0x7FE, 0x7FF];

/// Injecte des valeurs frontières dans l'APID (11 bits de l'ID). L'APID pilote
/// le routage Software Bus vers l'application cFS destinataire — c'est le
/// champ qui décide où le paquet atterrit, ou s'il se perd. 0x7FF est
/// spécial : c'est l'"idle packet" du standard CCSDS, que le récepteur doit
/// explicitement ignorer.
pub struct ApidMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for ApidMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];
        let r   = rng.next();

        let id_arg  = &mut input.commands[ci].args[0];
        let id      = parse_uint(&id_arg.value).unwrap_or(0) as u16;
        let new_apid = APID_BOUNDARIES[r as usize % APID_BOUNDARIES.len()];
        let new_id  = set_bits(id, 0, 11, new_apid);
        id_arg.value = format!("0x{new_id:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for ApidMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("ApidMutator") }
}

// ─── 11. SeqFlagsMutator ─────────────────────────────────────────────────────

/// Tire une valeur dans les 4 possibilités du champ Sequence Flags (2 bits du
/// SEQ). Nominal = 11 (paquet complet, non segmenté) ; 00/01/10 annoncent de
/// la segmentation (continuation / premier / dernier segment) et testent la
/// gestion du réassemblage côté cFS.
pub struct SeqFlagsMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for SeqFlagsMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];
        let r   = rng.next();

        let seq_arg = &mut input.commands[ci].args[1];
        let seq     = parse_uint(&seq_arg.value).unwrap_or(0) as u16;
        let new_seq = set_bits(seq, 14, 2, (r % 4) as u16);
        seq_arg.value = format!("0x{new_seq:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for SeqFlagsMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("SeqFlagsMutator") }
}

// ─── 12. SeqCountMutator ─────────────────────────────────────────────────────

const SEQCOUNT_BOUNDARIES: &[u16] = &[0, 1, 0x2000, 0x3FFE, 0x3FFF];

/// Injecte des valeurs frontières dans le Sequence Count (14 bits du SEQ).
/// Sert à la détection de perte de paquets côté récepteur ; teste le
/// wrap-around du compteur (0x3FFF → 0) et la détection de discontinuité.
pub struct SeqCountMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for SeqCountMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<usize> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz && cmd.args.len() > 1)
            .map(|(ci, _)| ci)
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng = state.rand_mut();
        let ci  = targets[rng.next() as usize % targets.len()];
        let r   = rng.next();

        let seq_arg   = &mut input.commands[ci].args[1];
        let seq       = parse_uint(&seq_arg.value).unwrap_or(0) as u16;
        let new_count = SEQCOUNT_BOUNDARIES[r as usize % SEQCOUNT_BOUNDARIES.len()];
        let new_seq   = set_bits(seq, 0, 14, new_count);
        seq_arg.value = format!("0x{new_seq:04X}").into_bytes();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for SeqCountMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("SeqCountMutator") }
}

// ─── Sélection de mutateur configurable (fuzz_config.toml → mutators) ────────

/// Identifie un mutateur pour la sélection depuis `fuzz_config.toml`. Les noms
/// suivent la convention snake_case du TOML (ex: `"arg_value"`, `"seq_count"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutatorKind {
    ArgValue,
    FcWalk,
    IntBoundary,
    StringSpecial,
    CommandReorder,
    Delay,
    Version,
    PacketType,
    SecHdrFlag,
    Apid,
    SeqFlags,
    SeqCount,
}

impl MutatorKind {
    /// Liste complète proposée par `fuzz_config.toml` — valeur par défaut
    /// utilisée si le champ `mutators` est absent de la config.
    pub const ALL: &'static [MutatorKind] = &[
        MutatorKind::ArgValue,
        MutatorKind::FcWalk,
        MutatorKind::IntBoundary,
        MutatorKind::StringSpecial,
        MutatorKind::CommandReorder,
        MutatorKind::Delay,
        MutatorKind::Version,
        MutatorKind::PacketType,
        MutatorKind::SecHdrFlag,
        MutatorKind::Apid,
        MutatorKind::SeqFlags,
        MutatorKind::SeqCount,
    ];
}

/// Applique, à chaque appel de `mutate`, un seul mutateur parmi ceux
/// sélectionnés dans `fuzz_config.toml` (`kinds`) :
///   - une seule entrée dans `kinds`  → toujours ce mutateur-là, pour tous les
///     paquets mutés.
///   - plusieurs entrées dans `kinds` → un mutateur tiré au hasard dans cette
///     liste à chaque paquet muté.
pub struct SelectedMutator {
    kinds:           Vec<MutatorKind>,
    arg_value:       ArgValueMutator,
    fc_walk:         FcWalkMutator,
    int_boundary:    IntBoundaryMutator,
    string_special:  StringSpecialMutator,
    command_reorder: CommandReorderMutator,
    delay:           DelayMutator,
    version:         VersionMutator,
    packet_type:     PacketTypeMutator,
    sec_hdr_flag:    SecHdrFlagMutator,
    apid:            ApidMutator,
    seq_flags:       SeqFlagsMutator,
    seq_count:       SeqCountMutator,
}

impl SelectedMutator {
    pub fn new(kinds: Vec<MutatorKind>) -> Self {
        assert!(!kinds.is_empty(), "fuzz_config.toml: `mutators` ne peut pas être vide");
        Self {
            kinds,
            arg_value:       ArgValueMutator,
            fc_walk:         FcWalkMutator,
            int_boundary:    IntBoundaryMutator,
            string_special:  StringSpecialMutator,
            command_reorder: CommandReorderMutator,
            delay:           DelayMutator,
            version:         VersionMutator,
            packet_type:     PacketTypeMutator,
            sec_hdr_flag:    SecHdrFlagMutator,
            apid:            ApidMutator,
            seq_flags:       SeqFlagsMutator,
            seq_count:       SeqCountMutator,
        }
    }
}

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for SelectedMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let kind = if self.kinds.len() == 1 {
            self.kinds[0]
        } else {
            let idx = state.rand_mut().next() as usize % self.kinds.len();
            self.kinds[idx]
        };

        match kind {
            MutatorKind::ArgValue       => self.arg_value.mutate(state, input),
            MutatorKind::FcWalk         => self.fc_walk.mutate(state, input),
            MutatorKind::IntBoundary    => self.int_boundary.mutate(state, input),
            MutatorKind::StringSpecial  => self.string_special.mutate(state, input),
            MutatorKind::CommandReorder => self.command_reorder.mutate(state, input),
            MutatorKind::Delay          => self.delay.mutate(state, input),
            MutatorKind::Version        => self.version.mutate(state, input),
            MutatorKind::PacketType     => self.packet_type.mutate(state, input),
            MutatorKind::SecHdrFlag     => self.sec_hdr_flag.mutate(state, input),
            MutatorKind::Apid           => self.apid.mutate(state, input),
            MutatorKind::SeqFlags       => self.seq_flags.mutate(state, input),
            MutatorKind::SeqCount       => self.seq_count.mutate(state, input),
        }
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for SelectedMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("SelectedMutator") }
}
