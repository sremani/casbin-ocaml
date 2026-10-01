#!/usr/bin/env python3
"""Check an explicit corpus against both CLIs, with no skipped oracle failures."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = "524f3f2dc9baef696d748db491d49b3055d359d1"


def check_pin():
    source = ROOT / "upstream" / "casbin"
    for arguments, expected in [
        (["rev-parse", "HEAD"], PIN + "\n"),
        (["status", "--porcelain", "--untracked-files=all"], ""),
    ]:
        result = subprocess.run(["git", "-C", str(source), *arguments],
                                text=True, capture_output=True, timeout=10)
        if result.returncode != 0 or result.stdout != expected:
            raise ValueError("upstream must be an unmodified checkout of " + PIN)
    module = (ROOT / "oracle" / "go.mod").read_text()
    if "replace github.com/casbin/casbin/v3 => ../upstream/casbin" not in module:
        raise ValueError("Go oracle must use the pinned local upstream replacement")


def check_result(executable, arguments, expected):
    try:
        result = subprocess.run([str(executable), *arguments], text=True,
                                capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)
    if expected == "error":
        correct = (result.returncode == 2 and result.stdout == ""
                   and bool(result.stderr.strip()))
    else:
        correct = (result.returncode == 0 and result.stderr == ""
                   and result.stdout == ("true\n" if expected else "false\n"))
    if correct:
        return None
    return (f"expected {expected!r}; exit={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocaml", type=Path,
                        default=ROOT / "_build/default/bin/main.exe")
    parser.add_argument("--oracle", type=Path,
                        default=ROOT / "oracle/casbin-oracle")
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "test/fixtures/manifest.json")
    args = parser.parse_args()
    check_pin()
    manifest = json.loads(args.manifest.read_text())
    if (manifest.get("schema_version") != 1 or
            manifest.get("upstream", {}).get("commit") != PIN):
        raise ValueError("invalid manifest schema or upstream revision")
    fixtures = args.manifest.resolve().parent
    cases = manifest["cases"]
    if not cases:
        raise ValueError("empty corpus cannot certify compatibility")
    failures = []
    names = set()
    rejected = 0
    for case in cases:
        name = case["name"]
        if name in names:
            raise ValueError("duplicate case name: " + name)
        names.add(name)
        expected = case["expected"]
        oracle_expected = case.get("oracle_expected", expected)
        if not all(type(value) is bool or value == "error"
                   for value in (expected, oracle_expected)):
            raise ValueError("invalid expectation for " + name)
        if any(not isinstance(value, str) for value in case["request"]):
            raise ValueError("request values must be strings: " + name)
        paths = [(fixtures / case[field]).resolve() for field in ("model", "policy")]
        if any(not path.is_relative_to(fixtures) or not path.is_file() for path in paths):
            raise ValueError("missing or out-of-corpus fixture: " + name)
        arguments = [str(path) for path in paths] + case["request"]
        for label, executable, wanted in [
            ("Go", args.oracle.resolve(), oracle_expected),
            ("OCaml", args.ocaml.resolve(), expected),
        ]:
            error = check_result(executable, arguments, wanted)
            if error:
                failures.append(f"{name} [{label}]: {error}")
        if "oracle_expected" in case:
            if expected != "error":
                raise ValueError("oracle_expected is reserved for explicit unsupported cases")
            rejected += 1
    if failures:
        for failure in failures:
            print("FAIL " + failure, file=sys.stderr)
        print(f"{len(failures)} failed observations across {len(cases)} cases", file=sys.stderr)
        return 1
    print(f"PASS {len(cases)} cases: {len(cases) - rejected} parity cases, "
          f"{rejected} explicit unsupported rejections; both CLIs checked")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
