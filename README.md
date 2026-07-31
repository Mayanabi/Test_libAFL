# Maya LibAFL POC — Fuzzer NOS3

Fuzzer LibAFL qui envoie des télécommandes CCSDS à NOS3 (cFS) via UDP, et
observe les verdicts dans `maya_feedback.log` pour guider la mutation.

## Prérequis

NOS3 doit tourner (conteneurs Docker actifs, en particulier `sc01-nos-fsw`) :

```bash
cd /home/jstar/Desktop/github-nos3
make launch          # démarre NOS3
make stop            # arrête NOS3
```

Sans ça, tout ce qui suit échoue avec `IP NOS3 introuvable`.

---

## Vue d'ensemble : 4 façons d'envoyer des paquets

| Besoin                                                        | Outil                          |
|----------------------------------------------------------------|--------------------------------|
| Fuzzing automatique (mutation continue, guidé par feedback)    | `cargo run`                    |
| Fuzzing automatique + figer certains champs                    | `cargo run -- --fixed-fields`  |
| Envoyer **un seul** paquet fait main (faux flags, valeur précise) | `cargo run --bin send_packet`  |
| Rejouer une séquence connue (crash déjà observé)                | scripts Python (`replay_*.py`) |

---

## 1. Fuzzing automatique — `cargo run`

```bash
cargo run
```

Génère des séquences de commandes à partir du catalogue NOS3
(`catalogue_dump.json`), les mute automatiquement, les envoie via
`wrapper.py`, et garde en corpus tout ce qui produit un nouveau verdict.

Se configure entièrement dans **`fuzz_config.toml`** (pas besoin de
recompiler) :

- `mode` — `single_app`, `multi_app`, `all`, `cross_app`, `naive`, `stateful`
- `apps` — apps ciblées (mode `single_app`/`multi_app`)
- `mutators` — quels mutateurs utiliser (liste dans le fichier, ex:
  `arg_value`, `fc_walk`, `apid`, `seq_count`, ...)
- `seed_count`, `fuzz_priority`, etc.

**Ctrl+C** :
- 1 fois → annule la séquence en cours, redémarre NOS3 proprement, continue.
- 2 fois rapprochées → arrêt total.

Les crashes sont sauvegardés dans `./crashes/`.

---

## 2. Figer certains champs pendant le fuzzing — `--fixed-fields`

Pour laisser le fuzzing automatique tourner tout en imposant une valeur fixe
sur un champ précis (ex : garder un FC valide pendant que le reste mute) :

```bash
cargo run -- --fixed-fields fixed_fields.toml
```

`fixed_fields.toml` :

```toml
[[fixed]]
tc_name = "NOVATEL_OEM615_DISABLE_CC"   # optionnel : absent = toutes les commandes
field   = "FC"
value   = "0x05"
```

Chaque entrée est appliquée **après** la mutation automatique, à chaque
paquet généré. **Sans le flag `--fixed-fields`, aucun override n'est
appliqué** — le fuzzing reste 100% automatique. Pour changer, on relance
`cargo run` avec ou sans le flag (ou avec un autre fichier).

---

## 3. Envoyer un paquet unique fait main — `send_packet`

Pour tester un paquet précis (faux flags, valeur limite sur un champ...)
sans passer par une séquence complète ni par la boucle de fuzzing :

```bash
cargo run --bin send_packet                      # utilise one_shot.toml
cargo run --bin send_packet -- autre_spec.toml    # ou un autre fichier
```

`one_shot.toml` :

```toml
tc_name = "NOVATEL_OEM615_DISABLE_CC"   # template de départ (catalogue_dump.json)

[[overrides]]
name  = "FC"
value = "0xFF"

# [[overrides]]
# name  = "ID"
# value = "0x1806"
```

`tc_name` fournit le port, le target et les args par défaut depuis le
catalogue ; `overrides` ne modifie que les champs listés (`name` = le champ
tel qu'il apparaît dans `catalogue_dump.json` : `ID`, `SEQ`, `LEN`, `FC`,
`CHECKSUM`, ou un argument applicatif du TC). Le paquet est envoyé une seule
fois, et le verdict NOS3 s'affiche dans le terminal.

---

## 4. Rejouer une séquence connue — scripts Python

Pour reproduire un crash déjà observé, sans passer par Rust du tout :

```bash
python3 replay_from_log.py sequence.txt   # rejoue les lignes MsgId/FC d'un extrait de log
python3 replay_from_log.py                # ou colle les lignes via stdin

python3 replay_novatel_serial.py          # rejoue une séquence spécifique câblée en dur
```

Ces scripts parlent directement à NOS3 en UDP (via `CmdSender.py`), sans
passer par `wrapper.py` ni par LibAFL — utiles pour une reproduction rapide
et isolée d'un bug déjà trouvé.

---

## Autres commandes utiles

```bash
# Régénérer catalogue_dump.json depuis le catalogue NOS3 (après mise à jour du YAML)
python3 dump_catalogue.py

# Suivre les 50 dernières séquences envoyées par le fuzzer (utile en debug)
tail -f /tmp/maya_sequences.jsonl

# Suivre les verdicts NOS3 en direct
tail -f /home/jstar/Desktop/github-nos3/maya_feedback.log
```

---

## Structure du projet (pour s'y retrouver)

```
src/
  main.rs        → boucle de fuzzing principale (cargo run)
  bin/
    send_packet.rs → envoi manuel d'un paquet unique (cargo run --bin send_packet)
  config.rs      → chargement de fuzz_config.toml / fixed_fields.toml
  catalogue.rs    → chargement de catalogue_dump.json
  generator.rs    → génère les séquences de commandes (normal/naive/cross_app/stateful)
  input.rs        → structures CCSDS + tous les mutateurs
  executor.rs      → pont vers wrapper.py (subprocess)
  feedback.rs      → interprète les verdicts NOS3 pour guider le corpus
  fsm.rs           → machines d'état (mode stateful)

wrapper.py        → reçoit le JSON depuis Rust, envoie en UDP, lit le verdict
fuzz_config.toml  → config du fuzzing automatique
fixed_fields.toml → champs figés en post-processing (--fixed-fields)
one_shot.toml     → paquet unique à envoyer (send_packet)
catalogue_dump.json → catalogue des TC NOS3 (généré par dump_catalogue.py)
```
