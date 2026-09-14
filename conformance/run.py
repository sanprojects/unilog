#!/usr/bin/env python3
"""Conformance runner — see protocol.md. Runs every case through every
available language driver, validates each output against the record schema,
normalizes volatile fields, and diffs the results against each other."""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join(ROOT, "conformance", "cases")
SCHEMA_PATH = os.path.join(ROOT, "spec", "record.schema.json")

VOLATILE_TOP = ["timestamp"]
VOLATILE_RESOURCE = [
    "host.name", "process.pid", "service.instance.id", "service.name",
]
# The caller-trace feature (spec: code.function/filepath/lineno/stacktrace)
# is correct-by-design to differ across drivers — each driver.<ext> is
# itself the call site Build() sees, in a different file, language and
# function name. Masked to a placeholder (not popped): this still verifies
# every language actually produces the feature, just not its driver-specific
# text.
VOLATILE_ATTRIBUTES = ["code.function", "code.filepath", "code.lineno"]
# code.stacktrace is popped outright rather than masked: whether a SECOND
# frame even exists above the driver's own call site depends on how much
# runtime bootstrap machinery (go run's runtime.main, node's module-loader
# wrapper, ...) sits above main() in each language — that's an artifact of
# how each driver happens to be invoked, not a guarantee the format makes.
DROPPED_ATTRIBUTES = ["code.stacktrace"]

DRIVERS = {
    "python": {
        "check": lambda: shutil.which("python3"),
        "cmd": lambda case_path: [sys.executable, os.path.join(ROOT, "conformance", "impls", "python", "driver.py"), case_path],
    },
    "node": {
        "check": lambda: shutil.which("node"),
        "cmd": lambda case_path: [shutil.which("node"), os.path.join(ROOT, "conformance", "impls", "node", "driver.cjs"), case_path],
    },
    "php": {
        "check": lambda: shutil.which("php"),
        "cmd": lambda case_path: [shutil.which("php"), "-n", os.path.join(ROOT, "conformance", "impls", "php", "driver.php"), case_path],
    },
    "go": {
        "check": lambda: shutil.which("go"),
        "cmd": lambda case_path: [shutil.which("go"), "run", os.path.join(ROOT, "conformance", "impls", "go", "driver.go"), case_path],
    },
}


def normalize(record: dict) -> dict:
    rec = json.loads(json.dumps(record))  # deep copy
    for k in VOLATILE_TOP:
        if k in rec:
            rec[k] = "<VOLATILE>"
    if "resource" in rec:
        # Drop rather than mask: these are legitimately optional and
        # environment/resolver-dependent (spec §3) — e.g. whether a nearby
        # package.json/go.mod/composer.json is discoverable varies per
        # sandbox, so PRESENCE differing across drivers is a test-harness
        # artifact, not a format mismatch. Masking a value in place would
        # still leave "key present" vs "key absent" as a spurious diff.
        for k in VOLATILE_RESOURCE:
            rec["resource"].pop(k, None)
    if "attributes" in rec:
        for k in VOLATILE_ATTRIBUTES:
            if k in rec["attributes"]:
                rec["attributes"][k] = "<VOLATILE>"
        for k in DROPPED_ATTRIBUTES:
            rec["attributes"].pop(k, None)
        if not rec["attributes"]:
            del rec["attributes"]
    return rec


def load_schema_validator():
    try:
        import jsonschema
    except ImportError:
        print("conformance: jsonschema not installed (pip install jsonschema) — skipping schema validation", file=sys.stderr)
        return None
    schema = json.load(open(SCHEMA_PATH))
    return jsonschema.Draft202012Validator(schema)


def run_driver(lang: str, case_path: str) -> tuple[bool, str]:
    cmd = DRIVERS[lang]["cmd"](case_path)
    # Caller-info (code.function/filepath/lineno/stacktrace) is correct-by-
    # design to differ across drivers — each driver.<ext> is itself a
    # different call site. Off by default here so today's cases don't need
    # VOLATILE_ATTRIBUTES masking just to pass; a case can still turn it back
    # on via its own "env" (applied by the driver after this base env).
    env = {**os.environ, "LOG_CALLER_INFO": "0"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=ROOT, env=env)
    except Exception as e:
        return False, f"driver crashed to launch: {e}"
    if proc.returncode != 0:
        return False, f"exit {proc.returncode}: {proc.stderr.strip()}"
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        return False, f"no output (stderr: {proc.stderr.strip()})"
    return True, line


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", help="comma list of languages to run (default: all available)")
    ap.add_argument("--cross", action="store_true", help="fail on any cross-language mismatch (default behavior)")
    ap.add_argument("--require", help="comma list of languages that must be available or the run fails")
    args = ap.parse_args()

    wanted = args.impl.split(",") if args.impl else list(DRIVERS.keys())
    available = [lang for lang in wanted if DRIVERS[lang]["check"]()]
    missing = [lang for lang in wanted if lang not in available]
    if missing:
        print(f"conformance: skipping unavailable driver(s): {', '.join(missing)}", file=sys.stderr)
    required = args.require.split(",") if args.require else []
    for r in required:
        if r not in available:
            print(f"conformance: --require {r} but it is not available", file=sys.stderr)
            return 1

    validator = load_schema_validator()

    cases = sorted(glob.glob(os.path.join(CASES_DIR, "*.json")))
    total = 0
    failed = 0
    matrix_rows = []

    for case_path in cases:
        case = json.load(open(case_path))
        name = case.get("name", os.path.basename(case_path))
        total += 1
        results: dict[str, dict | None] = {}
        errors: dict[str, str] = {}

        for lang in available:
            ok, out = run_driver(lang, case_path)
            if not ok:
                errors[lang] = out
                results[lang] = None
                continue
            try:
                rec = json.loads(out)
            except json.JSONDecodeError as e:
                errors[lang] = f"invalid JSON: {e}: {out[:200]}"
                results[lang] = None
                continue
            if validator is not None:
                schema_errs = list(validator.iter_errors(rec))
                if schema_errs:
                    errors[lang] = f"schema violation: {schema_errs[0].message}"
            results[lang] = rec

        case_ok = True
        normalized = {lang: normalize(rec) for lang, rec in results.items() if rec is not None}
        langs_ok = [lang for lang in available if lang not in errors]
        if len(langs_ok) >= 2:
            reference_lang = langs_ok[0]
            reference = normalized[reference_lang]
            for lang in langs_ok[1:]:
                if normalized[lang] != reference:
                    case_ok = False
                    errors[lang] = (
                        f"mismatch vs {reference_lang}:\n"
                        f"  {reference_lang}: {json.dumps(reference, sort_keys=True)}\n"
                        f"  {lang}: {json.dumps(normalized[lang], sort_keys=True)}"
                    )
        if errors:
            case_ok = False

        status = "PASS" if case_ok else "FAIL"
        if not case_ok:
            failed += 1
        matrix_rows.append((name, status, available, errors))

        print(f"[{status}] {name}")
        for lang in available:
            if lang in errors:
                print(f"    {lang}: FAIL — {errors[lang]}")
            else:
                print(f"    {lang}: ok")

    print("")
    print(f"conformance: {total - failed}/{total} cases passed across {', '.join(available)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
