#!/usr/bin/env python3
"""Seeded corpus expansions; both real implementations and every output are checked.

python3 scripts/stress_gauntlet.py --seed 401 --count 2000
No builds or downloads are performed. Build all six probes with verify.sh first.
Expectations come from observed parity corpus anchors, never from either run.
Failures retain standalone fixtures and complete inputs/outputs; --replay reuses them.
"""
import argparse
import copy
import csv
import decimal
import hashlib
import io
import json
import math
import os
import platform
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from verify_abac import encode_ocaml
from verify_management import encode_operations
from verify_oracle import PIN, ROOT, check_pin

AREAS = {"enforcement": "fixtures", "management": "management", "abac": "abac"}
# These are opaque principals/actions from existing examples, never effect values.
WORDS = ("alice", "bob", "carol", "dave", "eve", "reader", "writer", "admin", "read", "write")
WORD_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(WORDS) + r")(?![A-Za-z0-9_])")
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def policy_rows(source):
    """Physical-line CSV, matching the supported file adapter's valid inputs."""
    result = []
    for line in source.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            result.append(next(csv.reader([line], skipinitialspace=True)))
    return result


def write_rows(rows):
    output = io.StringIO()
    csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
    return output.getvalue()


def fields(model):
    found = re.search(r"(?m)^p\s*=\s*([^\n#]+)", model)
    return [x.strip() for x in found.group(1).split(",")] if found else []


def opaque_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for child in value:
            yield from opaque_strings(child)
    elif isinstance(value, dict):
        for child in value.values():
            yield from opaque_strings(child)


def load_anchors():
    anchors = {}
    for family, area in AREAS.items():
        directory = ROOT / "test" / area
        manifest = json.loads((directory / "manifest.json").read_text())
        if manifest["schema_version"] != 1 or manifest["upstream"]["commit"] != PIN:
            raise ValueError("invalid anchor manifest: " + area)
        names = set()
        selected = []
        for case in manifest["cases"]:
            if case["name"] in names:
                raise ValueError("duplicate anchor: " + case["name"])
            names.add(case["name"])
            # This is a declared generation domain, not a skip after a failing run.
            # Boundaries and error-only/initialization anchors stay in the full corpora.
            if "oracle_expected" in case or case.get("initial_error"):
                continue
            if family != "management" and type(case["expected"]) is not bool:
                continue
            if family == "management" and "error" in case["expected"]:
                continue
            item = copy.deepcopy(case)
            for key in ("model", "policy"):
                path = (directory / case[key]).resolve()
                if not path.is_relative_to(directory) or not path.is_file():
                    raise ValueError("out-of-corpus anchor path")
                item[key + "_source"] = path.read_text()
            rows = policy_rows(item["policy_source"])
            payloads = [cell for row in rows for cell in row]
            payloads += list(opaque_strings(item.get("request", [])))
            payloads += [arg for op in item.get("operations", []) for arg in op["args"]]
            # Collision and NUL-cache gauntlets remain explicit full-corpus tests.
            # These generated cases stay inside clean parity compositions.
            if any("," in value or "\0" in value for value in payloads):
                continue
            item["family"] = family
            item["anchor"] = case["name"]
            selected.append(item)
        if not selected:
            raise ValueError("empty supported anchor family: " + family)
        anchors[family] = selected
    return anchors


def rename_function(case, index, rng):
    """Injective alpha renaming; disable any name that is a longer prefix/key."""
    payload = canonical(case)
    model = case["model_source"]
    suffix = rng.choice(("ascii", "é", "漢", "Ω"))
    prefix = "luigi_" + str(index) + "_" + str(rng.randrange(1 << 32)) + "_"
    allowed = set()
    # Prefix relationships can connect a renamed whole word to an unrenamed
    # shorter pattern (a* -> alice, read* -> reader). Preserve every opaque
    # string in keyMatch models; other safe mutations still exercise them.
    has_keymatch = bool(re.search(r"\bkeyMatch\s*\(", model))
    for word in WORDS:
        if has_keymatch:
            continue
        if case["family"] == "abac" and re.search(r"[<>]", model):
            continue
        # A keyMatch prefix must not get renamed without its longer matching key.
        if re.search(r"\b" + re.escape(word) + r"[A-Za-z0-9_]", payload):
            continue
        # Leave schema/model/property names and preprocessing names intact.
        if re.search(r"\." + re.escape(word) + r"\b", model):
            continue
        if word in fields(model) or word in case.get("request_schema", {}):
            continue
        allowed.add(word)
    mapping = {word: prefix + word + "_" + suffix for word in WORDS if word in allowed}
    def rename(value):
        return WORD_RE.sub(lambda found: mapping.get(found.group(1), found.group(1)), value)
    return rename, mapping


def map_values(value, rename):
    if isinstance(value, str):
        return rename(value)
    if isinstance(value, list):
        return [map_values(child, rename) for child in value]
    if isinstance(value, dict):
        # Schema/property keys are structural and intentionally remain unchanged.
        return {name: map_values(child, rename) for name, child in value.items()}
    return value


def map_trace(lines, operations, rename):
    result = []
    for line, operation in zip(lines, operations):
        if line.startswith("rows\t"):
            payload = line[5:]
            rows = [[rename(bytes.fromhex(x).decode("utf-8")) for x in row.split(",")]
                    for row in payload.split(";")] if payload else []
            result.append("rows\t" + ";".join(",".join(x.encode("utf-8").hex() for x in row) for row in rows))
        elif line.startswith("values\t"):
            payload = line[7:]
            values = [rename(bytes.fromhex(x).decode("utf-8")) for x in payload.split(",")] if payload else []
            values.sort(key=lambda x: x.encode("utf-8"))
            result.append("values\t" + ",".join(x.encode("utf-8").hex() for x in values))
        else:
            result.append(line)
    return result


SUPPORTED_EFFECTS = {
    "some(where(p.eft==allow))",
    "!some(where(p.eft==deny))",
    "some(where(p.eft==allow))&&!some(where(p.eft==deny))",
    "priority(p.eft)||deny",
}


def supported_effect(model):
    match = re.search(r"(?m)^e\s*=\s*([^\n#]+)", model)
    expression = re.sub(r"\s+", "", match.group(1)) if match else ""
    return expression if expression in SUPPORTED_EFFECTS else None


def offset_priority(case, rng):
    """An order-preserving numeric shift with injective raw rank spellings."""
    model = case["model_source"]
    # A raw priority cell may also be an ordinary matcher string operand.
    # Shifting its rank would change that comparison, even if sort order holds.
    # Only the declared four effect strategies have established order semantics.
    if supported_effect(model) is None or re.search(r"\bp\s*\.\s*priority\b|\bp_priority\b", model):
        return False
    definition = fields(model)
    if "priority" not in definition:
        return False
    column = definition.index("priority")
    rows = policy_rows(case["policy_source"])
    values = [row[column + 1] for row in rows if row[0] == "p"]
    if case["family"] == "management":
        for op in case["operations"]:
            if op["op"] in ("add_policy", "remove_policy", "has_policy"):
                if len(op["args"]) != len(definition):
                    return False
                values.append(op["args"][column])
    if not values or any(not re.fullmatch(r"[+-]?[0-9]+", value) for value in values):
        return False
    numbers = [int(value) for value in values]
    if min(numbers) < INT64_MIN or max(numbers) > INT64_MAX:
        return False
    lower, upper = max(-10000, INT64_MIN - min(numbers)), min(10000, INT64_MAX - max(numbers))
    delta = rng.randint(lower, upper)
    by_number = {}
    mapping = {}
    for raw in dict.fromkeys(values):
        shifted = int(raw) + delta
        alias = by_number.get(shifted, 0)
        by_number[shifted] = alias + 1
        magnitude = "0" * alias + str(abs(shifted))
        mapping[raw] = ("-" if shifted < 0 else "+") + magnitude
    for row in rows:
        if row[0] == "p":
            row[column + 1] = mapping[row[column + 1]]
    case["policy_source"] = write_rows(rows)
    if case["family"] == "management":
        for op, line_index in zip(case["operations"], range(len(case["expected"]))):
            if op["op"] in ("add_policy", "remove_policy", "has_policy"):
                op["args"][column] = mapping[op["args"][column]]
            if op["op"] == "get_policy":
                line = case["expected"][line_index]
                payload = line[5:]
                expected_rows = [row.split(",") for row in payload.split(";")] if payload else []
                for row in expected_rows:
                    raw = bytes.fromhex(row[column]).decode("utf-8")
                    row[column] = mapping[raw].encode("utf-8").hex()
                case["expected"][line_index] = "rows\t" + ";".join(",".join(row) for row in expected_rows)
    case["priority_offset"] = delta
    return True


NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_.])(-?\s*(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+))(?![A-Za-z0-9_.])")
LITERAL_RE = re.compile(r"(['\"])(.*?)\1")


def scale_typed_numbers(case, rng):
    """Positive powers of two preserve finite numeric comparisons exactly.

    Apply the same scaling to native request numbers and unquoted matcher
    numbers. Reject a transform with overflow, underflow or rounded collisions.
    Scientific request transport is fine; matcher replacements stay decimal.
    """
    if case["family"] != "abac":
        return False
    numbers = []
    def collect(value):
        if type(value) in (int, float):
            numbers.append(float(value))
        elif isinstance(value, list):
            for child in value:
                collect(child)
        elif isinstance(value, dict):
            for child in value.values():
                collect(child)
    collect(case["request"])
    # Protect quoted strings from numeric transformations.
    chunks = []
    position = 0
    for match in LITERAL_RE.finditer(case["model_source"]):
        chunks += [(False, case["model_source"][position:match.start()]), (True, match.group(0))]
        position = match.end()
    chunks.append((False, case["model_source"][position:]))
    for quoted, text in chunks:
        if not quoted:
            numbers += [float(re.sub(r"\s+", "", match.group(0))) for match in NUMBER_RE.finditer(text)]
    if not numbers:
        return False
    factor = rng.choice((0.25, 0.5, 2.0, 4.0))
    scaled = [value * factor for value in numbers]
    if any(not math.isfinite(value) for value in scaled):
        return False
    if len(set(scaled)) != len(set(numbers)) or any(old != 0 and new == 0 for old, new in zip(numbers, scaled)):
        return False
    def transform(value):
        if type(value) in (int, float):
            return float(value) * factor
        if isinstance(value, list):
            return [transform(child) for child in value]
        if isinstance(value, dict):
            return {key: transform(child) for key, child in value.items()}
        return value
    def replace(match):
        value = float(re.sub(r"\s+", "", match.group(0))) * factor
        return format(decimal.Decimal(str(value)), "f")
    case["request"] = transform(case["request"])
    case["model_source"] = "".join(text if quoted else NUMBER_RE.sub(replace, text) for quoted, text in chunks)
    case["numeric_factor"] = factor
    return True


def expand(anchor, index, rng):
    case = copy.deepcopy(anchor)
    rename, mapping = rename_function(case, index, rng)
    case["name"] = "luigi-" + str(index) + "-" + case["anchor"]
    case["renaming"] = mapping
    # Only literal contents can be renamed in the matcher; r/p identifiers stay fixed.
    case["model_source"] = re.sub(r"(['\"])(.*?)\1", lambda match: match.group(1) + rename(match.group(2)) + match.group(1), case["model_source"])
    case["policy_source"] = rename(case["policy_source"])
    if case["family"] == "management":
        for op in case["operations"]:
            op["args"] = map_values(op["args"], rename)
        case["expected"] = map_trace(case["expected"], case["operations"], rename)
    else:
        case["request"] = map_values(case["request"], rename)
    if rng.randrange(2) == 0:
        offset_priority(case, rng)
    scale_typed_numbers(case, rng)
    # Exact duplicate rows preserve first-wins identity and graph validation order.
    # No random cycle/self link or malformed tuple is ever introduced.
    rows = policy_rows(case["policy_source"])
    if rows and rng.randrange(2) == 0:
        row = rng.choice(rows)
        case["policy_source"] += ("" if case["policy_source"].endswith("\n") else "\n") + write_rows([row])
        case["duplicate_row"] = row
    # All-effects order invariance only: no implicit priority, numeric ties, or
    # comma-key collision order is changed. Management exposes stored row order.
    if case["family"] != "management" and supported_effect(case["model_source"]) in SUPPORTED_EFFECTS - {"priority(p.eft)||deny"}:
        keys = [",".join(row) for row in rows]
        if len(set(keys)) == len(keys) and rng.randrange(3) == 0:
            rng.shuffle(rows)
            case["policy_source"] = write_rows(rows)
            case["policy_permuted"] = True
    return case


def invocation(case, paths):
    if case["family"] == "management":
        input_go = input_ocaml = encode_operations(case["operations"])
        expected = "".join(line + "\n" for line in case["expected"])
        extra = []
    elif case["family"] == "abac":
        input_go = json.dumps(case["request"], ensure_ascii=True, allow_nan=False) + "\n"
        input_ocaml = encode_ocaml(case["request_schema"], case["request"])
        expected = "true\n" if case["expected"] else "false\n"
        extra = []
    else:
        input_go = input_ocaml = None
        expected = "true\n" if case["expected"] else "false\n"
        extra = case["request"]
    return [str(path) for path in paths] + extra, {"go": input_go, "ocaml": input_ocaml}, expected


def diagnostic_text(value):
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def run(executable, arguments, input_text, timeout):
    started = time.monotonic()
    try:
        result = subprocess.run([str(executable), *arguments], input=input_text,
                                capture_output=True, text=True, timeout=timeout)
        return {"returncode": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr, "seconds": time.monotonic() - started}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"returncode": None, "stdout": diagnostic_text(getattr(error, "stdout", None)),
                "stderr": diagnostic_text(getattr(error, "stderr", None)), "exception": repr(error),
                "seconds": time.monotonic() - started}


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=401)
    parser.add_argument("--count", type=int, default=2000, help="number of generated cases/sequences")
    parser.add_argument("--output", type=Path, default=ROOT / ".cache/stress-gauntlet.json")
    parser.add_argument("--log", type=Path, help="complete JSONL diagnostics; defaults beside report")
    parser.add_argument("--replay", type=Path, help="replay a saved failure/case JSON")
    parser.add_argument("--timeout", type=float, default=15)
    for language in ("go", "ocaml"):
        for family in AREAS:
            default = {("go", "enforcement"): "oracle/casbin-oracle", ("go", "management"): "oracle/casbin-management-oracle", ("go", "abac"): "oracle/casbin-abac-oracle", ("ocaml", "enforcement"): "_build/default/bin/main.exe", ("ocaml", "management"): "_build/default/bin/management_probe.exe", ("ocaml", "abac"): "_build/default/bin/abac_probe.exe"}[language, family]
            parser.add_argument("--" + language + "-" + family, type=Path, default=ROOT / default)
    args = parser.parse_args()
    if args.count <= 0 or args.timeout <= 0:
        parser.error("count and timeout must be positive")
    args.output = args.output.resolve()
    log_path = args.log.resolve() if args.log else args.output.with_suffix(".jsonl")
    if log_path == args.output:
        parser.error("report and log paths must differ")
    report = {"schema_version": 1, "seed": args.seed, "requested_cases": 1 if args.replay else args.count,
              "upstream_commit": PIN, "status": "running", "completed_cases": 0,
              "case_counts": {}, "errors": [], "disagreements": [], "expectation_mismatches": [], "failure_reproductions": [],
              "log": str(log_path), "operation_steps": 0, "expected_true_outputs": 0,
              "expected_false_outputs": 0, "coverage": {}, "checksums": {}}
    started = time.monotonic()
    hashes = {name: hashlib.sha256() for name in ("expected", "go", "ocaml", "cases")}
    counts, anchor_counts, variants, features = Counter(), Counter(), Counter(), Counter()
    try:
        subprocess.run([str(ROOT / "scripts/check_toolchain.sh")], check=True, capture_output=True, text=True)
        check_pin()
        anchors = load_anchors()
        binaries = {(language, family): getattr(args, language + "_" + family).resolve()
                    for language in ("go", "ocaml") for family in AREAS}
        for path in binaries.values():
            if not path.is_file() or not os.access(path, os.X_OK):
                raise ValueError("missing executable: " + str(path))
        report["provenance"] = {"script_sha256": digest(Path(__file__)),
                                "machine": {"system": platform.system(), "machine": platform.machine(), "platform": platform.platform(), "python": platform.python_version()},
                                "command": [sys.executable, *sys.argv],
                                "manifest_sha256": {area: digest(ROOT / "test" / area / "manifest.json") for area in AREAS.values()},
                                "binary_sha256": {language + "_" + family: digest(path) for (language, family), path in binaries.items()},
                                "anchor_counts": {family: len(cases) for family, cases in anchors.items()}}
        rng = random.Random(args.seed)
        families = ("enforcement", "abac", "management", "enforcement", "abac", "enforcement", "management", "enforcement", "abac", "enforcement")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w") as log, tempfile.TemporaryDirectory(prefix="casbin-luigi-") as temporary:
            directory = Path(temporary)
            for index in range(1 if args.replay else args.count):
                if args.replay:
                    saved = json.loads(args.replay.read_text())
                    case = saved.get("case", saved)
                else:
                    family = families[index % len(families)]
                    case = expand(rng.choice(anchors[family]), index, rng)
                family = case["family"]
                paths = [directory / "model.conf", directory / "policy.csv"]
                for path, source in zip(paths, (case["model_source"], case["policy_source"])):
                    path.write_text(source)
                arguments, inputs, expected = invocation(case, paths)
                results = {language: run(binaries[language, family], arguments, inputs[language], args.timeout)
                           for language in ("go", "ocaml")}
                observed = {"index": index, "case": case, "inputs": inputs, "expected_stdout": expected, "results": results}
                log.write(json.dumps(observed, ensure_ascii=True) + "\n")
                log.flush()
                counts[family] += 1
                anchor_counts[family + "/" + case["anchor"]] += 1
                for feature, active in {"roles": "[role_definition]" in case["model_source"], "domains": bool(re.search(r"(?m)^g\s*=\s*_,\s*_,\s*_", case["model_source"])), "keyMatch": "keyMatch(" in case["model_source"], "priority_effect": "priority(p.eft)" in case["model_source"], "numeric_priority": "priority" in fields(case["model_source"]), "empty_policy": not policy_rows(case["policy_source"])}.items():
                    features[feature] += int(active)
                hashes["cases"].update((canonical(case) + "\n").encode("utf-8"))
                for variant in ("priority_offset", "duplicate_row", "policy_permuted", "numeric_factor"):
                    variants[variant] += int(variant in case)
                report["operation_steps"] += len(case.get("operations", []))
                report["expected_true_outputs"] += expected.splitlines().count("true")
                report["expected_false_outputs"] += expected.splitlines().count("false")
                frame = str(index) + "/" + case["name"] + "\n"
                hashes["expected"].update((frame + expected).encode("utf-8"))
                failures = []
                for language, result in results.items():
                    hashes[language].update((frame + result["stdout"]).encode("utf-8"))
                    if result["returncode"] != 0 or result["stderr"] or "exception" in result:
                        report["errors"].append({"index": index, "language": language, "result": result})
                        failures.append(language + " unexpected error/protocol failure")
                    if result["stdout"] != expected:
                        failures.append(language + " differs from independently observed expectation")
                        report["expectation_mismatches"].append({"index": index, "language": language, "expected_stdout": expected, "actual_stdout": result["stdout"]})
                if results["go"]["stdout"] != results["ocaml"]["stdout"]:
                    report["disagreements"].append({"index": index, "name": case["name"], "go": results["go"], "ocaml": results["ocaml"]})
                report["completed_cases"] += 1
                if failures:
                    reproduction = args.output.parent / (args.output.stem + "-failure-" + str(index))
                    reproduction.mkdir(parents=True, exist_ok=True)
                    (reproduction / "model.conf").write_text(case["model_source"])
                    (reproduction / "policy.csv").write_text(case["policy_source"])
                    save_json(reproduction / "case.json", observed)
                    for language, text in inputs.items():
                        if text is not None:
                            (reproduction / (language + "-stdin.txt")).write_text(text)
                    report["failure_reproductions"].append({"directory": str(reproduction), "failures": failures,
                        "replay": [sys.executable, str(Path(__file__).resolve()), "--replay", str(reproduction / "case.json"), "--output", str(reproduction / "replay.json")]})
                    report["status"] = "failed"
                    break
                if (index + 1) % 100 == 0:
                    print("checked " + str(index + 1) + " cases", file=sys.stderr, flush=True)
            else:
                report["status"] = "passed"
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["errors"].append({"stage": "harness", "exception": repr(error),
                                 "stdout": diagnostic_text(getattr(error, "stdout", None)),
                                 "stderr": diagnostic_text(getattr(error, "stderr", None))})
    report["case_counts"] = dict(counts)
    report["coverage"] = {"anchors_used": dict(anchor_counts), "variant_counts": dict(variants), "feature_counts": dict(features)}
    report["checksums"] = {name + "_sha256": value.hexdigest() for name, value in hashes.items()}
    report["seconds"] = time.monotonic() - started
    save_json(args.output, report)
    print(report["status"].upper() + " " + str(report["completed_cases"]) + " cases; " + str(report["operation_steps"]) + " management steps; report=" + str(args.output))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
