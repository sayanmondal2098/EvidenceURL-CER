"""Guarded E02 mode launcher; it refuses an unfrozen comparison."""
import json, sys
from pathlib import Path
mode=Path(sys.argv[1]).resolve() if len(sys.argv)==2 else None
if not mode or not mode.is_file(): raise SystemExit("usage: run_mode.py path/to/mode.json")
record=json.loads(mode.read_text(encoding="utf-8"))
if record.get("status", "").startswith("NOT_RUN") or record.get("run_status") != "RUN_READY":
    raise SystemExit("REFUSED: "+record.get("status", "mode is not frozen/runnable"))
raise SystemExit("A RUN_READY adapter has not been supplied by this package.")
