"""Minimal E02 manifest validator; does not train models."""
import json, sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)==2 else "../run_manifest.json")
r=json.loads(p.read_text(encoding="utf-8"))
required={"experiment","run_status","source_hashes","adapters","same_partition_required"}
missing=required-set(r)
if missing: raise SystemExit("invalid manifest; missing "+repr(sorted(missing)))
print(r["run_status"])
