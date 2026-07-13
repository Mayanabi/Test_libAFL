#!/usr/bin/env python3
"""
Rejoue une séquence directement depuis les lignes du maya_feedback.log.

Usage :
    python3 replay_from_log.py sequence.txt   # depuis un fichier
    python3 replay_from_log.py                # depuis stdin (coller-coller les lignes)
"""
import sys, re, socket, time
sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev')
import CmdSender

PORT  = 5012
DELAY = 0.1  # 10ms entre chaque paquet

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip   = CmdSender.getDockerIP()

# Parse "OK MsgId=0x1870 FC=7" ou "DROP_SB_ERROR MsgId=0x0000 FC=0 ..."
pattern = re.compile(r'MsgId=(0x[0-9A-Fa-f]+)\s+FC=(\d+)')

def send_packet(msgid: str, fc: int):
    args = [
        {"NAME": "CCSDS_STREAMID", "TYPE": "UINT", "SIZE": "16", "VALUE": msgid,  "ENDIANNESS": ""},
        {"NAME": "CCSDS_SEQUENCE", "TYPE": "UINT", "SIZE": "16", "VALUE": "0xC000","ENDIANNESS": ""},
        {"NAME": "CCSDS_LENGTH",   "TYPE": "UINT", "SIZE": "16", "VALUE": "1",     "ENDIANNESS": ""},
        {"NAME": "CCSDS_FC",       "TYPE": "UINT", "SIZE": "8",  "VALUE": str(fc), "ENDIANNESS": ""},
        {"NAME": "CCSDS_CHECKSUM", "TYPE": "UINT", "SIZE": "8",  "VALUE": "0",     "ENDIANNESS": ""},
    ]
    try:
        CmdSender.sendCommand(args, "CFS", PORT, ip, sock)
        print(f"  → MsgId={msgid}  FC={fc}")
    except Exception as e:
        print(f"  ! MsgId={msgid}  FC={fc}  ERREUR: {e}")

lines = open(sys.argv[1]).readlines() if len(sys.argv) > 1 else sys.stdin.readlines()
matches = [pattern.search(l) for l in lines]
total = sum(1 for m in matches if m)

print(f"Cible : {ip}:{PORT}")
print(f"Envoi de {total} paquets...\n")

for m in matches:
    if not m:
        continue
    send_packet(m.group(1), int(m.group(2)))
    time.sleep(DELAY)

print("\nTerminé — vérifie le terminal NOS3.")
