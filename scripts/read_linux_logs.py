import sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)>1 else "/var/log/auth.log")
if not p.is_file(): raise SystemExit(f"Log not found: {p}")
print("\n".join(p.read_text(errors="replace").splitlines()[-200:]))
