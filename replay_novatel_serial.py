#!/usr/bin/env python3
"""
Rejoue la séquence complète qui a causé le Device read error NOVATEL_OEM615.

Séquence observée dans le terminal NOS3 :
  1. Invalid MsgId(0xfffe) x2  — APID corrompu
  2. NOVATEL_OEM615 NOOP       — FC=0x00
  3. NOVATEL_OEM615 FC=0x12    — "Invalid command code" (hors plage valide 0-7)
  4. Invalid MsgId(0x0)        — APID corrompu
  → Device read error

  5. NOVATEL_OEM615 SERIALCONFIG_CC — FC=0x07
  → Second Device read error
"""
import sys, socket, time
sys.path.insert(0, '/home/jstar/Desktop/fuzzer/input_generator_dev')
import CmdSender

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip   = CmdSender.getDockerIP()
PORT = 5012

def send(label, streamid, fc):
    args = [
        {"NAME": "CCSDS_STREAMID", "TYPE": "UINT", "SIZE": "16", "VALUE": streamid, "ENDIANNESS": ""},
        {"NAME": "CCSDS_SEQUENCE", "TYPE": "UINT", "SIZE": "16", "VALUE": "0xC000",  "ENDIANNESS": ""},
        {"NAME": "CCSDS_LENGTH",   "TYPE": "UINT", "SIZE": "16", "VALUE": "1",       "ENDIANNESS": ""},
        {"NAME": "CCSDS_FC",       "TYPE": "UINT", "SIZE": "8",  "VALUE": fc,        "ENDIANNESS": ""},
        {"NAME": "CCSDS_CHECKSUM", "TYPE": "UINT", "SIZE": "8",  "VALUE": "0",       "ENDIANNESS": ""},
    ]
    CmdSender.sendCommand(args, "CFS", PORT, ip, sock)
    print(f"  → {label}")
    time.sleep(0.1)

print(f"Cible : {ip}:{PORT}")
print()

# ── Séquence 1 → premier Device read error ────────────────────────────────────
send("APID=0xFFFE (Invalid MsgId)",                    "0xFFFE", "0x00")
send("APID=0xFFFE (Invalid MsgId)",                    "0xFFFE", "0x00")
send("NOVATEL_OEM615 NOOP           (FC=0x00)",        "0x1870", "0x00")
send("NOVATEL_OEM615 FC=0x12        (hors plage!)",    "0x1870", "0x12")
send("APID=0x0000 (Invalid MsgId)",                    "0x0000", "0x00")

print()
print(">>> Vérifie le terminal NOS3 — Device read error attendu ici <<<")
time.sleep(1.0)
print()

# ── Séquence 2 → second Device read error ─────────────────────────────────────
send("NOVATEL_OEM615 SERIALCONFIG_CC (FC=0x07)",       "0x1870", "0x07")

print()
print(">>> Vérifie le terminal NOS3 — second Device read error attendu ici <<<")
