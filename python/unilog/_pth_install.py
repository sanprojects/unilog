"""`unilog-enable-pth` console script — the "maximal" install mode from the
spec: drops a .pth file into site-packages so *every* Python process in this
venv gets unilog, not just ones that `import unilog.auto` explicitly.

Trade-off, spelled out on purpose: this also affects pip/pytest/other tools
in the same venv, and is skipped entirely by `python -S`. Use `import
unilog.auto` unless you specifically want that reach.
"""

from __future__ import annotations

import site
import sys


def main() -> int:
    targets = site.getsitepackages() if hasattr(site, "getsitepackages") else [site.getusersitepackages()]
    if not targets:
        print("unilog: no site-packages directory found", file=sys.stderr)
        return 1
    target = targets[0]
    path = f"{target}/unilog.pth"
    # .pth quirk: site.py exec()s each "import "-prefixed line independently —
    # no real if-block across lines — so this has to be one expression.
    with open(path, "w") as f:
        f.write("import os; os.environ.get('UNILOG_DISABLE') or __import__('unilog.auto')\n")
    print(f"unilog: wrote {path}")
    print("Every Python process started in this environment will now load unilog automatically.")
    print("Remove that file, or set UNILOG_DISABLE=1, to turn it back off.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
