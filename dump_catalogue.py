#!/usr/bin/env python3
"""

Exporte le catalogue NOS3 (nos3_commands_reference.yaml) en JSON plat
pour que Rust puisse le charger via serde_json dans src/catalogue.rs.

"""

import json
import sys
import os

_ADAPTER_DIR = "/home/jstar/Desktop/maya3/catalogue/adapters"
_YAML_PATH   = "/home/jstar/Desktop/maya3/catalogue/nos3_commands_reference.yaml"

sys.path.insert(0, _ADAPTER_DIR)
from nos3_adapter import load_nos3_catalogue  # type: ignore[import-not-found]

output_path = sys.argv[1] if len(sys.argv) > 1 else "catalogue_dump.json"

catalogue = load_nos3_catalogue(_YAML_PATH)

with open(output_path, "w") as f:
    json.dump(catalogue, f, indent=2)

print(f"Catalogue exporté : {len(catalogue)} TC → {output_path}")

# Résumé par priorité
for prio in ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"]:
    n = sum(1 for t in catalogue.values() if t.get("fuzz_priority") == prio)
    print(f"  {prio:8s} : {n} TC")
