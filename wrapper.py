#!/usr/bin/env python3
"""
WRAPPER.PY — Maya 3.0 (branché sur CmdSender + maya_feedback.log)

Reçoit sur stdin le JSON CcsdsSequenceInput sérialisé par Nos3Executor.
Envoie TOUTES les commandes de la séquence vers NOS3/cFS via UDP, dans l'ordre,
en respectant les délais inter-commandes.
Répond sur stdout une ligne JSON {"verdict": "<v1>|<v2>|..."} où chaque vi
est le verdict NOS3 pour la commande i.

En mode single_app/all : séquence d'une commande → verdict simple "OK".
En mode cross_app      : séquence multi-apps → verdict combiné "OK|DROP_SB_ERROR|OK".
Le verdict combiné est traité comme une chaîne unique par Nos3Feedback — chaque
nouvel ordre/combinaison de verdicts est donc considéré intéressant.

Prérequis : container Docker "sc01-nos-fsw" actif (NOS3 lancé).
"""

import json
import os
import random
import socket
import subprocess
import sys
import time

#ajout explicite au path car wrapper.py est appelé comme subprocess depuis
#un répertoire arbitraire par LibAFL.
_CMDSENDER_DIR = "/home/jstar/Desktop/fuzzer/input_generator_dev"
sys.path.insert(0, _CMDSENDER_DIR)
import CmdSender        # noqa: E402  # type: ignore[import-not-found]
import ProcessMonitoring  # noqa: E402  # type: ignore[import-not-found]

# Répertoire du repo NOS3 (contient le Makefile : make stop / make launch)
_NOS3_DIR      = "/home/jstar/Desktop/github-nos3"
# Log écrit par ci_lab_app.c (chemin hardcodé côté cFS, voir ci_lab_app.c:186)
_LOG_PATH      = "/home/jstar/Desktop/github-nos3/maya_feedback.log"
_POLL_INTERVAL   = 0.005  # 5 ms entre chaque lecture du log
_POLL_TIMEOUT    = 1.0    # 1 s max avant de déclarer TIMEOUT (executor timeout = 5 s)
_RESTART_WAIT    = 90.0   # temps max d'attente que cFS réponde après make launch
_RESTART_POLL    = 2.0    # intervalle de vérification pendant le restart
_MAKE_TIMEOUT    = 180.0  # temps max pour chacun de make stop / make launch

# Endianness Rust → format attendu par CmdSender.py
_ENDIAN = {"BIG": "BIG_ENDIAN", "LITTLE": "LITTLE_ENDIAN"}

# IP et PID résolus une seule fois par Rust au démarrage, passés via env vars.
_NOS3_IP   = os.environ.get("NOS3_IP")      or CmdSender.getDockerIP()
_INIT_PID  = os.environ.get("NOS3_CFS_PID") or ProcessMonitoring.get_cfs_pid()
_FUZZ_MODE = os.environ.get("FUZZ_MODE", "normal")  # si pas configuré par défaut c normal

# Socket UDP réutilisé pour toute la durée du processus.
_SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _to_sender_arg(arg: dict) -> dict:
    """
    Convertit un CcsdsArg (JSON Rust, clés snake_case) vers le dict attendu
    par CmdSender.sendCommand() (clés MAJUSCULES).
    """
    return {
        "NAME":       arg["name"],
        "TYPE":       arg["arg_type"],      # ex: "UINT", "FLOAT", "STRING", "BLOCK"
        "SIZE":       str(arg["size_bits"]), # CmdSender attend une string, pas un int
        "VALUE":      arg["value"],
        "ENDIANNESS": _ENDIAN.get(arg.get("endianness") or "", ""),  # None ou absent → défaut du target
    }


def _log_offset() -> int:
    """positionn de lecture de départ du log """
    try:
        return os.path.getsize(_LOG_PATH)
    except OSError:
        return 0


def _poll_log(start: int, msgid_hex: str) -> str:
    """
    Attend une ligne dans le log après la position `start` contenant `msgid_hex`.

    Paramètre msgid_hex : ex "0x1806" (4 chiffres hex majuscules). Si vide,
    retourne la première nouvelle ligne trouvée (APID corrompu par le fuzzer).

    ci_lab_app.c appelle fflush() après chaque fprintf → pas de buffering à gérer.
    Format MsgId dans le log : 0x%04X (OK/DROP_SB_ERROR) ou 0x%02X%02X
    (DROP_LEN_MISMATCH/DROP_BAD_SIZE) — les deux produisent la même chaîne pour
    un APID 16 bits.
    """
    # Fichier ouvert UNE seule fois — on utilise readline() en boucle (pattern
    # tail -f). Évite des centaines d'appels open()/close() par exécution.
    # readline() retourne '' à EOF sans bloquer ; on dort _POLL_INTERVAL puis
    # on réessaie : quand ci_lab écrit une nouvelle ligne, elle devient visible.
    deadline = time.monotonic() + _POLL_TIMEOUT
    try:
        with open(_LOG_PATH, "r", errors="replace") as f:
            f.seek(start)
            while time.monotonic() < deadline:
                line = f.readline()
                if not line:                   # EOF — pas encore de nouvelle donnée
                    time.sleep(_POLL_INTERVAL)
                    continue
                line = line.rstrip()
                if not line:
                    continue
                if msgid_hex and f"MsgId={msgid_hex}" not in line:
                    continue
                tokens = line.split()
                if tokens:
                    return tokens[0]           # "OK", "DROP_LEN_MISMATCH", etc.
    except OSError:
        pass

    return "TIMEOUT"


def _wait_for_nos3_ready() -> None:
    """
    Force un redémarrage propre de NOS3 (make stop && make launch) après un
    crash, pour repartir toujours du même état initial connu, puis bloque
    jusqu'à ce que cFS réponde de nouveau.

    Appelée dès qu'un crash/restart est détecté, AVANT de retourner le verdict
    à LibAFL. LibAFL reste bloqué sur cette unique invocation de wrapper.py
    jusqu'au retour de cFS — les tests suivants ne repartent qu'une fois NOS3
    prêt, dans un état reproductible.
    """
    print("[wrapper.py] cFS crash — redémarrage NOS3 (make stop && make launch)...",
          file=sys.stderr)
    for target in ("stop", "launch"):
        try:
            subprocess.run(
                ["make", target],
                cwd=_NOS3_DIR,
                timeout=_MAKE_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print(f"[wrapper.py] 'make {target}' a dépassé {_MAKE_TIMEOUT}s",
                  file=sys.stderr)

    print(f"[wrapper.py] make launch terminé — attente cFS (max {_RESTART_WAIT}s)...",
          file=sys.stderr)
    deadline = time.monotonic() + _RESTART_WAIT
    while time.monotonic() < deadline:
        pid = ProcessMonitoring.get_cfs_pid()
        if pid is not None:
            print(f"[wrapper.py] NOS3 de nouveau disponible (PID={pid}), attente init...",
                  file=sys.stderr)
            time.sleep(2.0)  # laisser cFS finir son initialisation
            return
        time.sleep(_RESTART_POLL)
    print(f"[wrapper.py] NOS3 toujours absent après {_RESTART_WAIT}s", file=sys.stderr)


def _send_and_wait(cmd: dict) -> str:
    """
    Envoie cmd vers NOS3 et retourne le verdict NOS3 depuis le log.

    Si sendCommand() lève une exception (ex: VALUE corrompu → int() échoue
    dans convertIntToBytes), on retourne DROP_LEN_MISMATCH : le paquet n'a
    pas pu être construit, comportement équivalent à un drop côté NOS3.
    """
    args = [_to_sender_arg(a) for a in cmd["args"]]
    port = int(cmd["port"])

    # Calcul du MsgId pour la corrélation dans le log : ID = args[0] = APID (16 bits)
    try:
        apid_int  = int(args[0]["VALUE"], 0)
        msgid_hex = f"0x{apid_int:04X}"
    except (ValueError, IndexError, KeyError):
        # APID corrompu par le fuzzer — on cherche n'importe quelle nouvelle ligne
        msgid_hex = ""
        print(f"[wrapper.py] APID non parseable: {args[0].get('VALUE', '?')!r}",
              file=sys.stderr)

    try:
        start = _log_offset()
        CmdSender.sendCommand(args, "CFS", port, _NOS3_IP, _SOCK)
    except Exception as exc:
        # Ex: int() / float() / bytes.fromhex() échoue sur VALUE corrompu
        print(f"[wrapper.py] sendCommand() a échoué ({exc})", file=sys.stderr)
        return "DROP_LEN_MISMATCH"

    # Mode naïf : envoi sans attendre la réponse NOS3 → débit maximal
    if _FUZZ_MODE == "naive":
        return "NAIVE_OK"

    return _poll_log(start, msgid_hex)


_SEQ_LOG = "/tmp/maya_sequences.jsonl"
_SEQ_MAX  = 50   # garde les 50 dernières séquences

def _log_sequence(data: dict) -> None:
    """Écrit la séquence dans un fichier tournant (50 lignes max)."""
    try:
        try:
            with open(_SEQ_LOG) as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []
        lines.append(json.dumps(data) + "\n")
        with open(_SEQ_LOG, "w") as f:
            f.writelines(lines[-_SEQ_MAX:])
    except OSError:
        pass


def main() -> int:
    raw = sys.stdin.read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[wrapper.py] JSON invalide: {exc}", file=sys.stderr)
        print(json.dumps({"verdict": "DROP_LEN_MISMATCH"}))
        return 0

    _log_sequence(data)
    commands = data.get("commands", [])
    if not commands:
        print(json.dumps({"verdict": "DROP_LEN_MISMATCH"}))
        return 0

    verdicts = []

    for i, cmd in enumerate(commands):
        verdict = _send_and_wait(cmd)

        # Crash check — uniquement sur TIMEOUT pour éviter docker exec à chaque commande
        if verdict == "TIMEOUT" and _INIT_PID is not None:
            if not ProcessMonitoring.CheckProcessIsAlive(_INIT_PID):
                print(
                    f"[wrapper.py] cFS crash/restart après commande {i} "
                    f"({cmd.get('tc_name','?')}, PID={_INIT_PID})",
                    file=sys.stderr,
                )
                _wait_for_nos3_ready()
                print(json.dumps({"verdict": "CRASH"}))
                sys.stdout.flush()
                return 1

        verdicts.append(verdict)

        # Délai inter-commandes (respecte delay_min_ms / delay_max_ms du générateur)
        lo = cmd.get("delay_min_ms", 0)
        hi = cmd.get("delay_max_ms", 0)
        delay_ms = random.randint(lo, hi) if hi > lo else lo
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)

    # Verdict combiné : "OK|DROP_SB_ERROR|OK"
    # Chaque combinaison unique est traitée comme un nouveau comportement par Nos3Feedback.
    combined = "|".join(verdicts)
    print(json.dumps({"verdict": combined}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
