#!/usr/bin/env python3
"""Verify complete management traces on both probes, without skips."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from verify_oracle import PIN, ROOT, check_pin

OPERATIONS = {
    "enforce", "get_policy", "has_policy", "add_policy", "remove_policy",
    "get_grouping_policy", "has_grouping_policy", "add_grouping_policy",
    "remove_grouping_policy", "get_roles_for_user", "get_users_for_role",
}


def encode_operations(operations):
    lines = []
    for operation in operations:
        name = operation["op"]
        arguments = operation["args"]
        if name not in OPERATIONS or any(not isinstance(x, str) for x in arguments):
            raise ValueError("invalid management operation")
        lines.append(name + "".join("\t" + arg.encode("utf-8").hex() for arg in arguments))
    return "".join(line + "\n" for line in lines)


def check_trace(executable, model, policy, input_trace, expected, initial_error):
    try:
        result = subprocess.run([str(executable), str(model), str(policy)],
                                input=input_trace, capture_output=True, text=True,
                                timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        return [str(error)]
    if initial_error:
        if result.returncode == 2 and result.stdout == "" and result.stderr.strip():
            return []
        return [f"expected initialization error; exit={result.returncode}, "
                f"stdout={result.stdout!r}, stderr={result.stderr!r}"]
    errors = []
    if result.returncode != 0 or result.stderr:
        errors.append(f"expected exit 0 and empty stderr; exit={result.returncode}, "
                      f"stderr={result.stderr!r}")
    wanted = "".join(line + "\n" for line in expected)
    if result.stdout != wanted:
        actual = result.stdout.split("\n")
        if actual[-1] == "":
            actual.pop()
        for index in range(max(len(actual), len(expected))):
            got = actual[index] if index < len(actual) else "<missing>"
            want = expected[index] if index < len(expected) else "<unexpected output>"
            if got != want:
                errors.append(f"step {index + 1}: expected {want!r}, got {got!r}")
        if not result.stdout.endswith("\n") and expected:
            errors.append("stdout must end with a newline")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocaml", type=Path,
                        default=ROOT / "_build/default/bin/management_probe.exe")
    parser.add_argument("--oracle", type=Path,
                        default=ROOT / "oracle/casbin-management-oracle")
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "test/management/manifest.json")
    args = parser.parse_args()
    check_pin()
    manifest = json.loads(args.manifest.read_text())
    if (manifest.get("schema_version") != 1 or
            manifest.get("upstream", {}).get("commit") != PIN):
        raise ValueError("invalid management manifest schema or upstream pin")
    fixtures = args.manifest.resolve().parent
    cases = manifest["cases"]
    if not cases:
        raise ValueError("empty management corpus")
    names = set()
    failures = []
    steps = 0
    boundaries = 0
    for case in cases:
        name = case["name"]
        if name in names:
            raise ValueError("duplicate case: " + name)
        names.add(name)
        paths = [(fixtures / case[k]).resolve() for k in ("model", "policy")]
        if any(not p.is_relative_to(fixtures) or not p.is_file() for p in paths):
            raise ValueError("missing or out-of-corpus fixture for " + name)
        operations = case["operations"]
        initial_error = case.get("initial_error", False)
        if type(initial_error) is not bool:
            raise ValueError("initial_error must be Boolean")
        expected = case["expected"]
        oracle_expected = case.get("oracle_expected", expected)
        for lines in (expected, oracle_expected):
            if any(not isinstance(line, str) or "\n" in line for line in lines):
                raise ValueError("invalid expected trace for " + name)
            if len(lines) != (0 if initial_error else len(operations)):
                raise ValueError("expectation/operation length mismatch for " + name)
        if "oracle_expected" in case:
            if not case.get("boundary") or expected == oracle_expected:
                raise ValueError("explicit oracle trace requires a described difference: " + name)
            boundaries += 1
        input_trace = encode_operations(operations)
        for label, executable, wanted in [
            ("Go", args.oracle.resolve(), oracle_expected),
            ("OCaml", args.ocaml.resolve(), expected),
        ]:
            for failure in check_trace(executable, *paths, input_trace, wanted, initial_error):
                failures.append(f"{name} [{label}]: {failure}")
        steps += len(operations)
    if failures:
        for failure in failures:
            print("FAIL " + failure, file=sys.stderr)
        print(f"{len(failures)} failed observations across {len(cases)} management cases",
              file=sys.stderr)
        return 1
    print(f"PASS {len(cases)} management cases, {steps} operation steps, "
          f"{boundaries} explicit boundary traces; both probes checked")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
