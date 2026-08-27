#!/usr/bin/env python3
"""
Rejoue une séquence directement depuis les lignes du maya_feedback.log.

Envoie les octets CCSDS EXACTS capturés dans le log (après le "=>" de
chaque ligne), pas une reconstruction depuis MsgId/FC seuls avec des champs
par défaut — c'est le seul moyen de reproduire fidèlement un paquet dont les
arguments/payload ont été mutés par le fuzzer (ci_lab_app.c logge le paquet
complet reçu, pas juste son identité).

Format de ligne attendu (voir ci_lab_app.c, CI_LAB_Global.MayaLogFile) :
    OK {54379.618500976} MsgId=0x1000 FC=0 =>1000c00000010c00
    DROP_SB_ERROR {54380.19403343} MsgId=0xB910 FC=3 sb_status=-905969661 =>b910c00000010300

Les lignes DROP_LEN_MISMATCH / DROP_BAD_SIZE n'ont pas de hex de paquet dans
le log (rejetées avant reconstruction complète côté cFS) — elles sont
ignorées, il n'y a rien à rejouer pour elles.

Usage :
    python3 replay_from_log.py sequence.txt   # depuis un fichier
    python3 replay_from_log.py                # depuis stdin (coller les lignes)
"""
import sys, re, socket, time
sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev')
import CmdSender

PORT  = 5012
DELAY = 0.1  # 100ms entre chaque paquet

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip   = CmdSender.getDockerIP()

# Capture le verdict (OK/DROP_SB_ERROR/...), MsgId et FC (pour l'affichage
# uniquement) et le hex complet du paquet après "=>" (ce qui est réellement
# renvoyé).
pattern = re.compile(r'^(\S+).*MsgId=(0x[0-9A-Fa-f]+)\s+FC=(\d+).*=>([0-9A-Fa-f]+)\s*$')

def send_packet(verdict: str, msgid: str, fc: str, packet_hex: str):
    try:
        sock.sendto(bytes.fromhex(packet_hex), (ip, PORT))
        print(f"  → [{verdict}] MsgId={msgid} FC={fc} ({len(packet_hex) // 2} octets)")
    except Exception as e:
        print(f"  ! [{verdict}] MsgId={msgid} FC={fc} ERREUR: {e}")

lines = open(sys.argv[1]).readlines() if len(sys.argv) > 1 else sys.stdin.readlines()
matches = [pattern.search(l) for l in lines]
total = sum(1 for m in matches if m)

print(f"Cible : {ip}:{PORT}")
print(f"Envoi de {total} paquets (octets exacts du log)...\n")

for m in matches:
    if not m:
        continue
    verdict, msgid, fc, packet_hex = m.groups()
    send_packet(verdict, msgid, fc, packet_hex)
    time.sleep(DELAY)

print("\nTerminé — vérifie le terminal NOS3.")
