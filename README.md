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

## Vue d'ensemble : 7 façons d'envoyer des paquets

| Besoin                                                        | Outil                          |
|----------------------------------------------------------------|--------------------------------|
| Fuzzing automatique (mutation continue, guidé par feedback)    | `cargo run`                    |
| Fuzzing automatique + figer certains champs                    | `cargo run -- --fixed-fields`  |
| Fuzzing automatique à partir d'une séquence d'état connue      | `cargo run -- --component`     |
| Envoyer **un seul** paquet fait main (faux flags, valeur précise) | `cargo run --bin send_packet`  |
| Test différentiel HK (baseline / mutée / replay)                | `cargo run --bin hk_diff_test` |
| Rejouer un crash trouvé par le fuzzer (`./crashes/`)            | `python3 wrapper.py < crashes/<hash>` |
| Rejouer une séquence câblée en dur (bug déjà documenté)         | scripts Python (`replay_*.py`) |

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

- `apps` — apps ciblées (mode `single_app`/`multi_app`)
- `mutators` — quels mutateurs utiliser (liste dans le fichier, ex:
  `arg_value`, `fc_walk`, `apid`, `seq_count`, ...)
- `seed_count`, `fuzz_priority`, etc.

### `mode` — les 6 valeurs possibles

Une "exécution" = un appel à `wrapper.py` = une séquence de commandes
envoyées à la suite, sur le **même NOS3 qui continue de tourner** (NOS3 ne
redémarre QUE sur détection de crash — jamais entre deux exécutions
normales).

| mode         | catalogue utilisé                    | contenu d'une séquence (1 exécution)                                              |
|--------------|----------------------------------------|-------------------------------------------------------------------------------------|
| `single_app` | filtré sur `apps` (1 app)               | **1 commande**, tirée au hasard dans cette app                                     |
| `multi_app`  | filtré sur `apps` (plusieurs apps)      | **1 commande**, tirée au hasard parmi ces apps                                     |
| `all`        | catalogue complet (~315 TC, pas de filtre `apps`) | **1 commande par app** du catalogue, envoyées dans l'ordre alphabétique des apps (TC tirée au hasard dans chaque app) |
| `cross_app`  | catalogue complet (pas de filtre `apps`) | **N commandes** (`cross_app_min_tc` à `cross_app_max_tc`), apps et ordre **aléatoires** — teste les interactions app-à-app |
| `naive`      | catalogue complet                      | `naive_batch_size` commandes envoyées en rafale, sans attendre le feedback NOS3      |
| `stateful`   | catalogue complet, filtré par la FSM courante | 1 commande valide selon l'état courant de la machine d'états de l'app choisie |

`single_app`/`multi_app` ne diffèrent que par la taille de la liste `apps` —
dans les deux cas, une seule commande est envoyée par exécution. `all` et
`cross_app` envoient tous les deux plusieurs commandes par exécution, mais
`all` est **ordonné et déterministe** (une par app, ordre alphabétique)
tandis que `cross_app` est **aléatoire** (nombre, choix des apps et ordre
tirés au hasard à chaque exécution).

**Ctrl+C** :
- 1 fois → annule la séquence en cours, redémarre NOS3 proprement, continue.
- 2 fois rapprochées → arrêt total.

Les crashes sont sauvegardés dans `./crashes/`, directement en **JSON lisible**
(même format que celui envoyé à `wrapper.py`) — voir section 6 pour les rejouer.

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

## 3. Partir d'une séquence d'état connue — `--component`

Certains composants n'ont un comportement valide que si les commandes
arrivent dans un certain ordre (ex: NOVATEL_OEM615 : `NOOP` → `ENABLE` →
`LOG` → `UNLOG` → `RST_COUNTERS` → `DISABLE`). Plutôt que la génération
aléatoire depuis le catalogue complet, `--component` part directement d'une
de ces séquences connues, stockée dans `state_sequences/<COMPOSANT>.json` :

```bash
cargo run -- --list-components                                # composants disponibles dans le catalogue
cargo run -- --component NOVATEL_OEM615                       # fuzz toute la séquence
cargo run -- --component NOVATEL_OEM615 --start-step 3        # fige les étapes 1-2, mute à partir de l'étape 3
cargo run -- --component NOVATEL_OEM615 --start-step 3 --show # prévisualise la séquence (fuzz effectif) sans lancer NOS3
```

Chaque commande du fichier a un champ `fuzz` (`true`/`false`) qui décide si
elle peut être mutée — **tous** les mutateurs le respectent (y compris
`command_reorder` et `delay`, qui ne touchent/réordonnent que les commandes
`fuzz=true`), donc une commande `fuzz=false` reste garantie inchangée quel
que soit le mutateur tiré. `--start-step N` positionne ce champ
automatiquement (`fuzz=false` avant l'étape N, `fuzz=true` à partir de N)
sans avoir à éditer le JSON à la main.

Sans `--component`, comportement inchangé : génération selon `mode` dans
`fuzz_config.toml` (section 1).

---

## 4. Envoyer un paquet unique fait main — `send_packet`

Pour tester un paquet précis (faux flags, valeur limite sur un champ...)
sans passer par une séquence complète ni par la boucle de fuzzing :

```bash
cargo run --bin send_packet                      # utilise one_shot.toml
cargo run --bin send_packet -- autre_spec.toml    # ou un autre fichier
```

`tc_name` fournit le port, le target et les args par défaut depuis le
catalogue. Le reste de `one_shot.toml` colle à la structure réelle d'un
paquet CCSDS, en trois sections — chacune modifie une zone différente du
paquet, sans chevauchement ni ambiguïté :

```toml
tc_name = "NOVATEL_OEM615_DISABLE_CC"

[header]
sec_hdr_flag = 1
apid         = 0x1870

[secondary_header]
fc = "0xFF"

[[payload]]
name  = "NOM_DU_PARAM"
value = "valeur"
```

### `[header]` — header primaire CCSDS (48 bits : `ID` + `SEQ`)

Seul moyen de toucher `ID`/`SEQ` — même niveau de détail que les mutateurs
`version`/`packet_type`/`sec_hdr_flag`/`apid`/`seq_flags`/`seq_count`, sans
calculer le mot 16 bits à la main :

```toml
[header]
version      = 0        # 3 bits (0-7)
packet_type  = 1         # 1 bit  (0=TM, 1=TC)
sec_hdr_flag = 0         # 1 bit — 0 = pas de secondary header, 1 = présent
apid         = 0x1870    # 11 bits — adresse de routage cFS
seq_flags    = 3         # 2 bits (0-3)
seq_count    = 0         # 14 bits
```

Tous les champs sont optionnels — seuls ceux présents sont modifiés, le
reste du mot vient du template `tc_name`.

### `[secondary_header]` — Function Code + Checksum

N'a de sens que si `header.sec_hdr_flag = 1`. Remplace les anciens overrides
génériques sur `"FC"`/`"CHECKSUM"` :

```toml
[secondary_header]
fc       = "0xFF"
checksum = "0x00"
```

### `[[payload]]` — user data field (paramètres applicatifs du TC)

Pour les arguments propres au TC choisi (au-delà de `ID`/`SEQ`/`LEN`/`FC`/
`CHECKSUM`, qui ont leurs sections dédiées ci-dessus — un `[[payload]]` qui
cible l'un de ces noms est ignoré avec un avertissement) :

```toml
[[payload]]
name  = "NOM_DU_PARAM"   # nom de l'arg tel qu'il apparaît dans catalogue_dump.json
value = "valeur"          # envoyée telle quelle (ex: "0xFF", "1234", "toto")
```

Le paquet est envoyé une seule fois, et le verdict NOS3 s'affiche dans le terminal.

---

## 5. Test différentiel HK — `hk_diff_test`

Vérifie si une séquence mutée laisse un effet résiduel visible dans la HK
d'un composant : envoie une séquence connue, la mute, la renvoie, puis
renvoie la séquence ORIGINALE une seconde fois, et compare la HK capturée au
tout début à celle capturée après ce cycle.

```bash
cargo run --bin hk_diff_test                               # state_sequences/NOVATEL_OEM615.json par défaut
cargo run --bin hk_diff_test -- state_sequences/AUTRE.json  # un autre composant du catalogue (voir section 3)
```

Déroulement :

1. **Phase 1 (baseline)** — envoie la séquence originale, capture la HK.
2. Redémarre NOS3 (`make stop && make launch`) pour repartir d'un état interne propre avant la mutation.
3. **Phase 2 (mutée)** — mute la séquence (mêmes mutateurs que `cargo run`, configurés dans `fuzz_config.toml`), l'envoie, capture la HK.
4. **Phase 3 (replay)** — renvoie la séquence ORIGINALE, sans redémarrage depuis la phase 2 — c'est justement ce qui permet à un effet résiduel de la mutation de persister jusqu'ici, sinon la phase 3 ne pourrait jamais différer de la phase 1.
5. Diff automatique entre phase 1 et phase 3 : nombre de trames HK par app, contenu du dernier paquet HK par app, et tout `AttackTag` non nul.

Seule la **vraie HK** est capturée (`MsgId` de l'app ciblée avec `is_TC=0`) —
commandes, events EVS (ex: `MsgId=0808`, canal partagé texte) et trafic des
autres apps sur le bus sont exclus. Résultat dans `hk_phase1_baseline.csv` /
`hk_phase2_mutated.csv` / `hk_phase3_replay.csv` (tableau lisible, colonnes
alignées, hex des gros paquets tronqué avec le nombre d'octets omis).

---

## 6. Rejouer un crash trouvé par le fuzzer — `./crashes/`

Chaque crash détecté pendant `cargo run` est sauvegardé dans `./crashes/`
sous forme de fichier JSON (même format que ce que `wrapper.py` reçoit sur
stdin) — pas besoin d'outil, le fichier se lit directement (`cat` ou ouvrir
dans l'éditeur), et se rejoue tel quel :

```bash
cat crashes/1c2db06eb88b2a4c              # lisible directement
python3 wrapper.py < crashes/1c2db06eb88b2a4c   # renvoie exactement la même séquence à NOS3
```

Chaque hash a aussi deux fichiers annexes internes à LibAFL (à ignorer) :
`.{hash}` (compteur) et `.{hash}_1.metadata` (exec_time/executions).

Tout ce qui atterrit dans `./crashes/` est automatiquement en JSON — aucune
étape manuelle, aucune commande à lancer. C'est garanti par la surcharge de
`to_file`/`from_file` dans `src/input.rs` (voir `impl Input for
CcsdsSequenceInput`), qui remplace le format binaire par défaut de LibAFL.

---

## 7. Rejouer une séquence câblée en dur — scripts Python

Pour un bug déjà documenté/analysé, avec une séquence précise écrite à la main
(par opposition à un crash brut du fuzzer) :

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
  lib.rs         → ré-exports pour partager le code entre main.rs et les bin/
  bin/
    send_packet.rs  → envoi manuel d'un paquet unique (cargo run --bin send_packet)
    hk_diff_test.rs → test différentiel HK (cargo run --bin hk_diff_test)
  config.rs      → chargement de fuzz_config.toml / fixed_fields.toml
  catalogue.rs    → chargement de catalogue_dump.json
  generator.rs    → génère les séquences de commandes (normal/naive/cross_app/stateful/fixed)
  input.rs        → structures CCSDS + tous les mutateurs
  executor.rs      → pont vers wrapper.py (subprocess)
  feedback.rs      → interprète les verdicts NOS3 pour guider le corpus
  fsm.rs           → machines d'état (mode stateful)
  nos3_control.rs   → make stop / make launch (partagé main.rs + hk_diff_test.rs)
  state_catalogue.rs → catalogue de séquences d'état (state_sequences/, --component)

wrapper.py        → reçoit le JSON depuis Rust, envoie en UDP, lit le verdict
fuzz_config.toml  → config du fuzzing automatique
fixed_fields.toml → champs figés en post-processing (--fixed-fields)
one_shot.toml     → paquet unique à envoyer (send_packet)
catalogue_dump.json → catalogue des TC NOS3 (généré par dump_catalogue.py)
state_sequences/  → séquences d'état par composant, une JSON par composant (--component, section 3 ; hk_diff_test, section 5)
crashes/          → crashes trouvés par le fuzzer, en JSON rejouable (voir section 6)
```
