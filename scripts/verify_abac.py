#!/usr/bin/env python3
"""Check typed ABAC against native Go JSON values and the tagged OCaml probe."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from verify_oracle import PIN, ROOT, check_pin


def hex_string(value):
    if not isinstance(value, str):
        raise ValueError("schema/property names must be strings")
    return value.encode("utf-8").hex()


def encode_schema(schema):
    if isinstance(schema, dict):
        tokens = ["o", str(len(schema))]
        for name, child in schema.items():
            tokens += [hex_string(name)] + encode_schema(child)
        return tokens
    tags = {"string": "s", "number": "n", "bool": "b"}
    if not isinstance(schema, str) or schema not in tags:
        raise ValueError("invalid manifest schema descriptor")
    return [tags[schema]]


def encode_value(value):
    if value is None:
        return ["z"]
    if type(value) is bool:
        return ["b", "true" if value else "false"]
    if isinstance(value, str):
        return ["s", hex_string(value)]
    if type(value) in (int, float):
        return ["n", str(value)]
    if isinstance(value, list):
        tokens = ["a", str(len(value))]
        for child in value:
            tokens += encode_value(child)
        return tokens
    if isinstance(value, dict):
        tokens = ["o", str(len(value))]
        for name, child in value.items():
            tokens += [hex_string(name)] + encode_value(child)
        return tokens
    raise ValueError("unsupported manifest request value")


def encode_ocaml(request_schema, request):
    if not isinstance(request_schema, dict) or not isinstance(request, list):
        raise ValueError("request_schema must be a dict and request a native JSON array")
    schema_tokens = [str(len(request_schema))]
    for name, schema in request_schema.items():
        schema_tokens += [hex_string(name)] + encode_schema(schema)
    request_tokens = [str(len(request))]
    for value in request:
        request_tokens += encode_value(value)
    return "\t".join(schema_tokens) + "\n" + "\t".join(request_tokens) + "\n"


def check_result(executable, paths, input_text, expected):
    try:
        result = subprocess.run([str(executable), *map(str, paths)], input=input_text,
                                capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)
    if expected == "error":
        okay = result.returncode == 2 and result.stdout == "" and bool(result.stderr.strip())
    else:
        okay = (result.returncode == 0 and result.stderr == "" and
                result.stdout == ("true\n" if expected else "false\n"))
    if okay:
        return None
    return (f"expected {expected!r}; exit={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocaml", type=Path,
                        default=ROOT / "_build/default/bin/abac_probe.exe")
    parser.add_argument("--oracle", type=Path,
                        default=ROOT / "oracle/casbin-abac-oracle")
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "test/abac/manifest.json")
    args = parser.parse_args()
    check_pin()
    manifest = json.loads(args.manifest.read_text())
    if (manifest.get("schema_version") != 1 or
            manifest.get("upstream", {}).get("commit") != PIN):
        raise ValueError("invalid typed ABAC manifest schema or upstream revision")
    cases = manifest["cases"]
    if not cases:
        raise ValueError("empty ABAC corpus cannot certify compatibility")
    fixtures = args.manifest.resolve().parent
    names = set()
    boundaries = 0
    failures = []
    for case in cases:
        name = case["name"]
        if name in names:
            raise ValueError("duplicate ABAC case name: " + name)
        names.add(name)
        expected = case["expected"]
        oracle_expected = case.get("oracle_expected", expected)
        if not all(type(value) is bool or value == "error"
                   for value in (expected, oracle_expected)):
            raise ValueError("invalid expectation for " + name)
        if "oracle_expected" in case:
            if expected == oracle_expected or not case.get("boundary"):
                raise ValueError("explicit Go difference requires a boundary explanation: " + name)
            boundaries += 1
        paths = [(fixtures / case[field]).resolve() for field in ("model", "policy")]
        if any(not path.is_relative_to(fixtures) or not path.is_file() for path in paths):
            raise ValueError("missing or out-of-corpus ABAC fixture: " + name)
        # Native Go JSON decoding deliberately does not enable string reinterpretation.
        go_input = json.dumps(case["request"], ensure_ascii=True, allow_nan=False) + "\n"
        ocaml_input = encode_ocaml(case["request_schema"], case["request"])
        for label, executable, input_text, wanted in [
            ("Go", args.oracle.resolve(), go_input, oracle_expected),
            ("OCaml", args.ocaml.resolve(), ocaml_input, expected),
        ]:
            error = check_result(executable, paths, input_text, wanted)
            if error:
                failures.append(f"{name} [{label}]: {error}")
    if failures:
        for failure in failures:
            print("FAIL " + failure, file=sys.stderr)
        print(f"{len(failures)} failed observations across {len(cases)} ABAC cases", file=sys.stderr)
        return 1
    print(f"PASS {len(cases)} ABAC cases: {len(cases) - boundaries} parity cases, "
          f"{boundaries} explicit boundaries; native Go and typed OCaml checked")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
