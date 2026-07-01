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
/// Les renames seront validés à l'étape 5 (intégration réelle avec CmdSender).
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
/// intentionnelles — le fuzzer teste précisément comment NOS3 réagit à des
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
    // from_utf8_lossy : bytes non-UTF-8 → U+FFFD (Replacement Character).
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
    pub port:         u16,
    pub target:       String,
    pub mutation:     String,
    pub replay:       bool,
}

/// Input LibAFL : séquence ordonnée de commandes CCSDS.
///
/// Sérialisée en JSON avant d'être passée à wrapper.py via stdin.
/// Le corpus va se stabiliser à 2 entrées avec le vrai NOS3 (OK + DROP_LEN_MISMATCH),
/// contre ~4 avec la simulation actuelle.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, SerdeAny)]
pub struct CcsdsSequenceInput {
    pub commands: Vec<CcsdsCommand>,
}

impl Input for CcsdsSequenceInput {}

impl HasTargetBytes for CcsdsSequenceInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        OwnedSlice::from(serde_json::to_vec(self).expect("serialization should not fail"))
    }
}

// ─── Mutateurs ───────────────────────────────────────────────────────────────

// ─── Helper partagé ──────────────────────────────────────────────────────────

/// Parse une valeur ASCII décimale ou hexadécimale (0x…) vers u64.
/// Retourne None si la valeur est corrompue (non-UTF8, format invalide).
fn parse_uint(bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

// Tables de valeurs intéressantes par taille de champ.
// Couvrent : zéro, un, frontières signed/unsigned, max-1, max.
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
/// Complément des mutateurs sémantiques pour les types STRING et BLOCK
/// où il n'y a pas de structure numérique à exploiter.
pub struct ArgValueMutator;

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for ArgValueMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        // Construire la liste des cibles (ci, ai) dans les commandes fuzzables
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

// ─── 4. FloatSpecialMutator ──────────────────────────────────────────────────

/// Injecte des valeurs FLOAT spéciales (NaN, Inf, zéro, max) dans les args
/// de type FLOAT. Ces valeurs cassent souvent les traitements arithmétiques
/// dans les composants embarqués (divisions, comparaisons, sérialisation).
pub struct FloatSpecialMutator;

const FLOAT_SPECIAL: &[&str] = &[
    "0.0", "1.0", "-1.0",
    "3.4028235e38", "-3.4028235e38",   // float max / min
    "1.175494e-38",                     // float min normal
    "inf", "-inf", "nan",
];

impl<S: HasRand> Mutator<CcsdsSequenceInput, S> for FloatSpecialMutator {
    fn mutate(&mut self, state: &mut S, input: &mut CcsdsSequenceInput) -> Result<MutationResult, Error> {
        let targets: Vec<(usize, usize)> = input.commands.iter().enumerate()
            .filter(|(_, cmd)| cmd.fuzz)
            .flat_map(|(ci, cmd)| {
                cmd.args.iter().enumerate()
                    .filter(|(_, a)| matches!(a.arg_type, ArgType::Float))
                    .map(move |(ai, _)| (ci, ai))
            })
            .collect();
        if targets.is_empty() { return Ok(MutationResult::Skipped); }

        let rng      = state.rand_mut();
        let (ci, ai) = targets[rng.next() as usize % targets.len()];
        let r        = rng.next();

        input.commands[ci].args[ai].value =
            FLOAT_SPECIAL[r as usize % FLOAT_SPECIAL.len()].as_bytes().to_vec();
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> { Ok(()) }
}
impl Named for FloatSpecialMutator {
    fn name(&self) -> &Cow<'static, str> { &Cow::Borrowed("FloatSpecialMutator") }
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
