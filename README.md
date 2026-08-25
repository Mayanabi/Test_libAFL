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

Un redémarrage automatique de NOS3 (Ctrl+C simple, crash détecté, ou entre
les phases de `hk_diff_test`) lance `make launch` dans un nouveau
`gnome-terminal` — un environnement de bureau avec `gnome-terminal`
disponible est donc requis pour que ces redémarrages automatiques
fonctionnent (le code nettoie au passage les variables d'env `GTK_PATH`/
`SNAP*` pour éviter les conflits quand Claude/VSCode tourne dans un snap).

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
  `arg_value`, `fc_walk`, `apid`, `seq_count`, ...). Absent du fichier =
  tous les mutateurs, un tiré au hasard à chaque paquet muté.
- `fsm_dir` — dossier des définitions de machines d'état (YAML) utilisées en
  mode `stateful`. Par défaut `fsm/` (copié une fois depuis `maya3`, ce mode
  ne dépend plus d'un projet externe) ; un `.yaml` invalide dans ce dossier
  est simplement ignoré (message sur stderr), le fuzzing continue avec les
  FSM restantes.
- `naive_batch_size`, `cross_app_min_tc`, `cross_app_max_tc`, etc.

Le fuzzing part toujours d'une seule séquence initiale (générée selon `mode`,
ou chargée depuis `state_sequences/<COMPOSANT>.json` avec `--component`),
puis la boucle infinie (jusqu'à Ctrl+C) la mute et fait grossir le corpus au
fil des séquences jugées intéressantes — il n'y a pas de paramètre pour
partir de plusieurs seeds ni pour fournir une liste de seeds personnalisées.

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


`single_app`/`multi_app` ne diffèrent que par la taille de la liste `apps` —
dans les deux cas, une seule commande est envoyée par exécution. `all` et
`cross_app` envoient tous les deux plusieurs commandes par exécution, mais
`all` est **ordonné et déterministe** (une par app, ordre alphabétique —
seule la TC exacte tirée dans chaque app change à chaque exécution, l'ordre
des apps ne change jamais) tandis que `cross_app` est **aléatoire** (nombre,
choix des apps et ordre tirés au hasard à chaque exécution). En `cross_app`,
chaque app n'apparaît qu'une seule fois par séquence, et le nombre réel de
commandes est plafonné au nombre d'apps disponibles dans le catalogue filtré
même si `cross_app_max_tc` est plus grand.

### Mutateurs — précisions sur certains d'entre eux

La liste complète et leurs noms de clé TOML sont dans `fuzz_config.toml`.
Quelques comportements moins évidents à la lecture :

- `arg_value` (`ArgValueMutator`) et `int_boundary` (`IntBoundaryMutator`)
  mutent **tous** les args d'une commande fuzzable, y compris les 5 champs
  réservés `ID`/`SEQ`/`LEN`/`FC`/`CHECKSUM` (tous UINT) — pas seulement les
  paramètres applicatifs. C'est le seul moyen de fuzzer `LEN`, qui n'a pas de
  mutateur dédié.
- `fc_walk` (`FcWalkMutator`) : 1 chance sur 3 de sauter à une valeur FC
  totalement aléatoire (0-255), sinon incrémente/décrémente le FC courant de
  1 à 16.
- `apid`/`seq_count` (`ApidMutator`/`SeqCountMutator`) : tirent parmi 5
  valeurs frontières fixes (0, 1, milieu, max-1, max de la plage), pas une
  valeur aléatoire sur toute la plage — pour l'APID, `0x7FF` correspond au
  paquet CCSDS « idle », cas spécial du standard.

**Ctrl+C** :
- 1 fois → annule la séquence en cours et attend 3s (fenêtre pour un second
  Ctrl+C) avant de redémarrer NOS3 proprement et continuer. 
- 2 fois rapprochées → arrêt total.

Le redémarrage automatique **sur crash détecté** (pas Ctrl+C) est un chemin
différent : il est déclenché et géré côté Python, dans `wrapper.py`, dès
qu'un `TIMEOUT` est confirmé par la mort du process cFS — pas dans
`nos3_control.rs` (qui ne gère que Ctrl+C et `hk_diff_test`).

Les crashes sont sauvegardés dans `./crashes/`, directement en **JSON lisible**
(même format que celui envoyé à `wrapper.py`) — voir section 6 pour les rejouer.
Seul un `TIMEOUT` confirmé par la mort réelle du process cFS est traité comme
un crash ; un `TIMEOUT` de polling du log sans mort de process reste un
verdict normal (`ExitKind::Ok`), traité comme une entrée corpus classique et
**pas** sauvegardé dans `./crashes/`.

### Comment le feedback guide le corpus (`feedback.rs`)

Une séquence est gardée en corpus si la clé
`{tc_name de la 1ère commande}:{verdicts combinés de toutes les commandes}`
(ex: `"NOVATEL_OEM615_NOOP_CC:OK|DROP_SB_ERROR"`) n'a jamais été vue. Cette
clé ignore le nom des commandes 2, 3, ... d'une séquence multi-commandes
(modes `all`/`cross_app`) : seule la 1ère commande et l'enchaînement des
verdicts comptent pour la déduplication. Une séquence tuée par Ctrl+C est systématiquement exclue du corpus.

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
appliqué** — le fuzzing reste 100% automatique.

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

Le bit `sec_hdr_flag` (dans `[header]`) indique, au sens du standard
CCSDS/cFS, si un secondary header est présent — ce n'est pas une règle
inventée par cet outil. Mais **le code n'impose rien** : `[secondary_header]`
est appliqué tel quel même si `sec_hdr_flag = 0`, donc tu peux volontairement
envoyer un paquet incohérent (FC/CHECKSUM renseignés sans secondary header
déclaré) pour voir comment NOS3 réagit à ce cas normalement invalide :

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

### `delay_min_ms` / `delay_max_ms` (optionnels, top-level)

```toml
delay_min_ms = 0
delay_max_ms = 200
```

Contrôlent le délai avant l'envoi du paquet, comme le mutateur `delay` en
fuzzing automatique. Absents = pas de délai ajouté.

Le paquet est envoyé une seule fois, et le verdict NOS3 s'affiche dans le
terminal. Si un `[[payload]] name` ne correspond à aucun arg du TC choisi
(ou si `[secondary_header]` cible un TC sans secondary header), un
avertissement `[send_packet] champ '...' introuvable — ignoré` s'affiche
sur stderr et le champ est simplement ignoré (pas d'erreur bloquante).

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

1. **Phase 1 (baseline)** — envoie la séquence originale, capture la télémétrie.
2. Redémarre NOS3 (`make stop && make launch`) pour repartir d'un état interne propre avant la mutation.
3. **Phase 2 (mutée)** — mute la séquence (mêmes mutateurs que `cargo run`, configurés dans `fuzz_config.toml`), l'envoie, capture la télémétrie.
4. **Phase 3 (replay)** — renvoie la séquence ORIGINALE, sans redémarrage depuis la phase 2 — c'est justement ce qui permet à un effet résiduel de la mutation de persister jusqu'ici, sinon la phase 3 ne pourrait jamais différer de la phase 1.
5. Diff automatique entre phase 1 et phase 3 : nombre de trames par app, contenu du dernier paquet par app, et tout `AttackTag` non nul.

**Toute la télémétrie des apps ciblées est capturée** (`is_TC=0`), pas
seulement leur paquet HK périodique — les réponses ponctuelles comme
`DS_GET_FILE_INFO_CC` (info fichier) ou `TBL_SEND_REGISTRY_CC` (registre de
table) apparaissent aussi dans les CSV, **et leurs events EVS aussi** (ex:
`MsgId=0808`, canal texte partagé par toutes les apps — mais un event publié
via `CFE_EVS_SendEvent()` porte l'`AppId` de l'app appelante, pas un `AppId`
générique EVS, donc il est gardé si l'app est ciblée). Seuls les commandes
(`is_TC=1`) et le trafic — event EVS compris — des apps qui n'ont rien à voir
avec la séquence testée restent exclus : l'app source de chaque ligne est
identifiée par corrélation d'`AppId` avec son paquet HK (`hk_appids` dans
`hk_diff_test.rs`) — dans cFS, un app = un process = un seul AppId, partagé
par tout ce qu'il émet (HK, télémétrie ponctuelle, events). Résultat dans
`hk_phase1_baseline.csv` / `hk_phase2_mutated.csv` / `hk_phase3_replay.csv`

Le `MsgId` HK attendu pour chaque app (utilisé comme signal d'ancrage pour
la corrélation d'AppId ci-dessus, voir `expected_hk_msgids`) vient d'une
table (`CMD_TO_HK_MID` dans `hk_diff_test.rs`) construite à partir des
headers `*_msgids.h` du dépôt NOS3 — la vraie source de vérité, pas une
supposition — et couvre les 30 apps du catalogue. Ce n'est **pas** un simple
calcul (bit 12 à 0) : 8 apps sur 30 (CF, DS, ES, FM, LC, SBN, SC, SCH) ont un
`MsgId` HK qui ne se déduit pas directement du `MsgId` de commande. Si un
jour NOS3 ajoute une app absente de cette table, l'outil retombe sur ce
calcul approximatif et prévient sur stderr (`⚠ MsgId ... absent de
CMD_TO_HK_MID`).

Chaque phase attend au maximum 20s la HK attendue ; si rien n'arrive dans ce
délai, l'outil continue quand même et affiche `⚠` — dans ce cas l'AppId n'a
pas pu être corrélé et le CSV de cette phase reste vide, même si l'app a
émis d'autre télémétrie pendant la fenêtre.

---

## 6. Rejouer un crash trouvé par le fuzzer — `./crashes/`

Chaque crash détecté pendant `cargo run` est sauvegardé dans `./crashes/`
sous forme de fichier JSON (même format que ce que `wrapper.py` reçoit sur
stdin) :

```bash
cat crashes/1c2db06eb88b2a4c              # lisible directement
python3 wrapper.py < crashes/1c2db06eb88b2a4c   # renvoie exactement la même séquence à NOS3
```

Chaque hash a aussi deux fichiers annexes internes à LibAFL (à ignorer) :
`.{hash}` (compteur) et `.{hash}_1.metadata` (exec_time/executions).

Tout ce qui atterrit dans `./crashes/` est automatiquement en JSON — aucune
étape manuelle, aucune commande à lancer. 
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

## Structure du projet 

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
  nos3_control.rs   → make stop / make launch pour Ctrl+C et hk_diff_test.rs
                      (PAS le redémarrage automatique sur crash, voir wrapper.py)
  state_catalogue.rs → catalogue de séquences d'état (state_sequences/, --component)

wrapper.py        → reçoit le JSON depuis Rust, envoie en UDP, lit le verdict,
                     et gère lui-même le redémarrage NOS3 si un crash (process
                     cFS mort) est détecté
fuzz_config.toml  → config du fuzzing automatique
fixed_fields.toml → champs figés en post-processing (--fixed-fields)
one_shot.toml     → paquet unique à envoyer (send_packet)
catalogue_dump.json → catalogue des TC NOS3 (généré par dump_catalogue.py)
state_sequences/  → séquences d'état par composant, une JSON par composant (--component, section 3 ; hk_diff_test, section 5)
crashes/          → crashes trouvés par le fuzzer, en JSON rejouable (voir section 6)
```
