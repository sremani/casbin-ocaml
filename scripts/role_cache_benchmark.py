#!/usr/bin/env python3
"""Verify and reuse a paired receipt for a warm-role request-reuse control."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PIN = "524f3f2dc9baef696d748db491d49b3055d359d1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(root, arguments):
    return subprocess.check_output(arguments, cwd=root, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--rows", type=int, default=10000)
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--ocaml-binary", type=Path)
    parser.add_argument("--go-binary", type=Path)
    args = parser.parse_args()
    if args.rows <= 0 or args.iterations <= 0 or args.repeats < 5:
        parser.error("rows and iterations must be positive; repeats must be at least five")
    root = args.project_root.resolve()
    driver_path = Path(__file__).resolve()
    driver_digest = sha(driver_path)
    # Guard before reading or evaluating a reference, and never rebuild binaries.
    subprocess.run([str(root / "scripts/check_toolchain.sh")], cwd=root, check=True)
    upstream = root / "upstream/casbin"
    require(command(root, ["git", "-C", str(upstream), "rev-parse", "HEAD"]) == PIN,
            "upstream revision does not match the pinned source")
    require(command(root, ["git", "-C", str(upstream), "status", "--porcelain", "--untracked-files=all"]) == "",
            "upstream source must be clean")
    require("replace github.com/casbin/casbin/v3 => ../upstream/casbin" in (root / "oracle/go.mod").read_text(),
            "Go benchmark must use the pinned local replacement")
    reference_path = args.reference.resolve()
    require(args.output.resolve() != reference_path, "control output must differ from the main reference receipt")
    reference_digest = sha(reference_path)
    reference = json.loads(reference_path.read_text())
    require(reference.get("schema_version") == 2 and reference.get("profile") == "release",
            "reference must be a version-2 release benchmark receipt")
    require(reference.get("upstream_commit") == PIN, "reference upstream pin differs")
    versions = {"ocamlc": command(root, ["ocamlc", "-version"]),
                "ocamlopt": command(root, ["ocamlopt", "-version"]),
                "dune": command(root, ["dune", "--version"]), "go": command(root, ["go", "version"])}
    require(versions == reference["versions"], "tool versions differ from reference")
    provenance = reference["provenance"]
    required_sources = {str(path.relative_to(root)) for path in (root / "lib").glob("*.ml")}
    required_sources |= {str(path.relative_to(root)) for path in (root / "lib").glob("*.mli")}
    required_sources |= {"scripts/benchmark.py", "bin/benchmark.ml", "bin/benchmark_clock.c",
                         "oracle/benchmark/main.go", "oracle/go.mod", "oracle/go.sum",
                         "lib/dune", "bin/dune", "dune-project"}
    require(required_sources <= provenance["source_sha256"].keys(), "reference source fingerprint inventory is incomplete")
    for relative, expected in provenance["source_sha256"].items():
        path = (root / relative).resolve()
        require(path.is_relative_to(root) and path.is_file(), "missing/out-of-project source: " + relative)
        require(sha(path) == expected, "source hash differs from reference: " + relative)
    revision = command(root, ["git", "rev-parse", "HEAD"])
    status = command(root, ["git", "status", "--porcelain"])
    if provenance["project_status"] == "":
        require(status == "" and revision == provenance["project_revision"],
                "clean reference requires the same clean project revision")
        validation_mode = "same clean revision and source fingerprints"
    else:
        validation_mode = "working-tree source fingerprints; revision/status disclosed separately"
    build_directory = "_build"
    dune_command = provenance["build_commands"][0]
    if "--build-dir" in dune_command:
        build_directory = dune_command[dune_command.index("--build-dir") + 1]
    go_command = provenance["build_commands"][1]
    require("-o" in go_command, "reference does not identify the Go binary")
    go_path = Path(go_command[go_command.index("-o") + 1])
    if not go_path.is_absolute():
        go_path = root / "oracle" / go_path
    binaries = {"ocaml": (args.ocaml_binary or root / build_directory / "default/bin/benchmark.exe").resolve(),
                "go": (args.go_binary or go_path).resolve()}
    for language, binary in binaries.items():
        require(binary.is_file() and sha(binary) == provenance["binary_sha256"][language],
                language + " binary hash differs from reference")
    # Import the verified workload/protocol implementation from the project,
    # even when this control driver lives outside the clean project checkout.
    spec = importlib.util.spec_from_file_location("verified_benchmark", root / "scripts/benchmark.py")
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    environment = os.environ.copy()
    recorded_flags = reference["runtime"]["effective_flags"]
    require(all(key in recorded_flags for key in benchmark.RUNTIME_KEYS), "incomplete reference runtime flags")
    for key in benchmark.RUNTIME_KEYS:
        value = recorded_flags[key]
        if value is None:
            environment.pop(key, None)
        else:
            require(isinstance(value, str), "runtime flag must be string or null: " + key)
            environment[key] = value
    effective_runtime = {language: benchmark.runtime_info(binary, environment) for language, binary in binaries.items()}
    require(effective_runtime == reference["runtime"]["effective"], "effective GC/runtime settings differ from reference")
    require(effective_runtime["go"]["gomaxprocs"] == 1, "reference must use GOMAXPROCS=1")
    machine = benchmark.machine_info()
    if reference["machine"].get("affinity_cpus") is not None:
        require(machine["affinity_cpus"] == reference["machine"]["affinity_cpus"], "CPU affinity differs from reference")
    cold = [record for record in reference["results"]
            if record["scenario"] == "rbac-cold" and record["rows"] == args.rows]
    require(len(cold) == 2 and {record["language"] for record in cold} == set(binaries),
            "reference must contain both cold-role results for the selected identity count")
    require(args.repeats == reference["repeats"], "control repetitions must match reference")
    data = benchmark.workload("rbac-cold", args.rows, True)
    hashes = {"model_sha256": text_sha(data["model"]), "policy_sha256": text_sha(data["policy"]),
              "schema_sha256": text_sha(json.dumps(data["schema"], sort_keys=True, separators=(",", ":")))}
    cold_request_digest = text_sha(json.dumps(data["request"], sort_keys=True, separators=(",", ":")))
    for record in cold:
        require(all(record["input_sha256"][key] == value for key, value in hashes.items()),
                "cold reference model/policy/schema differs from regenerated control input")
        require(record["policy_rows"] == 1 and record["grouping_rows"] == args.rows + 9,
                "cold reference has an unexpected role graph")
        require(record["input_sha256"]["request_sha256"] == cold_request_digest
                and record["request"] == data["request"], "cold reference request strategy differs")
        require(record["warmup_operations"] == 1 and 0 < record["iterations"] <= args.rows
                and record["checksum"] == record["iterations"], "cold reference tuple/checksum invariant failed")
        require(len(record["seconds"]) == args.repeats and len(record["allocated_bytes"]) == args.repeats,
                "cold reference sample count differs")
        require(all(isinstance(value, (int, float)) and math.isfinite(value) and value > 0
                    for value in record["seconds"]), "invalid cold timing samples")
        require(all(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
                    for value in record["allocated_bytes"]), "invalid cold allocation samples")
    request = {"sub": "u0", "obj": "data", "act": "read"}
    hashes["request_sha256"] = text_sha(json.dumps(request, sort_keys=True, separators=(",", ":")))
    warmup = min(100, max(1, 500000 // args.rows))
    samples = {language: [] for language in binaries}
    allocations = {language: [] for language in binaries}
    orders = []
    with tempfile.TemporaryDirectory(prefix="casbin-role-cache-control-") as temporary:
        directory = Path(temporary)
        model_file, policy_file = directory / "model.conf", directory / "policy.csv"
        model_file.write_text(data["model"])
        policy_file.write_text(data["policy"])
        for repeat in range(args.repeats):
            order = ["ocaml", "go"] if repeat % 2 == 0 else ["go", "ocaml"]
            orders.append(order)
            for language in order:
                # Existing rbac logic repeats u0. The model/policy are the cold
                # workload's full identity graph, rather than its baseline graph.
                result = subprocess.run([str(binaries[language]), "rbac", str(model_file), str(policy_file),
                                         str(args.iterations), str(args.rows)], env=environment,
                                        capture_output=True, text=True, timeout=120)
                elapsed, allocated = benchmark.parse_result(result, "rbac", args.iterations, args.iterations)
                samples[language].append(elapsed)
                allocations[language].append(allocated)
    # Recheck immutable inputs/binaries and reference after all samples; a receipt
    # is not certified if the benchmark implementation changed during this run.
    require(sha(reference_path) == reference_digest, "reference changed during control run")
    require(sha(driver_path) == driver_digest, "control driver changed during run")
    for relative, expected in provenance["source_sha256"].items():
        require(sha(root / relative) == expected, "source changed during control run: " + relative)
    for language, binary in binaries.items():
        require(sha(binary) == provenance["binary_sha256"][language], "binary changed during control run: " + language)
    revision_after = command(root, ["git", "rev-parse", "HEAD"])
    status_after = command(root, ["git", "status", "--porcelain"])
    if provenance["project_status"] == "":
        require(status_after == "" and revision_after == revision,
                "clean project revision/status changed during control run")
    report = {"schema_version": 1, "captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "experiment": "warm-role request-reuse control", "upstream_commit": PIN, "profile": "release",
              "reference": {"path": str(reference_path), "sha256": reference_digest,
                            "project_revision": provenance["project_revision"], "project_status": provenance["project_status"]},
              "provenance": {"project_revision": revision, "project_status": status,
                             "project_revision_after": revision_after, "project_status_after": status_after,
                             "source_validation_mode": validation_mode, "source_sha256": provenance["source_sha256"],
                             "binary_sha256": provenance["binary_sha256"], "binary_paths": {name: str(path) for name, path in binaries.items()},
                             "driver_sha256": driver_digest,
                             "command": [sys.executable, *sys.argv]},
              "versions": versions, "machine": machine, "machine_after": benchmark.machine_info(),
              "runtime": {"effective_flags": recorded_flags, "effective": effective_runtime},
              "rows": args.rows, "iterations": args.iterations, "repeats": args.repeats,
              "input_sha256": hashes, "schema": data["schema"], "request": request,
              "cold_reference_records": cold, "sample_order": orders,
              "interpretation": "Same model, policy, schema, one permission row and full identity graph. Cold uses unique subjects after one disjoint sentinel warmup; warm reuses u0 after repeated warmup. Cold also formats each subject and constructs each request inside timing, while warm preconstructs its request. This changes request reuse and formatting as well as Go g-cache hits; it is not a pure isolated g-cache ablation.",
              "results": []}
    for language in binaries:
        median = statistics.median(samples[language])
        report["results"].append({"scenario": "rbac-warm-control", "binary_scenario": "rbac", "language": language,
            "rows": args.rows, "policy_rows": 1, "grouping_rows": args.rows + 9,
            "iterations": args.iterations, "warmup_operations": warmup, "checksum": args.iterations,
            "command_template": [str(binaries[language]), "rbac", "MODEL.conf", "POLICY.csv", str(args.iterations), str(args.rows)],
            "seconds": samples[language], "allocated_bytes": allocations[language],
            "median_seconds": median, "median_us_per_operation": median * 1e6 / args.iterations,
            "median_allocated_bytes_per_operation": statistics.median(allocations[language]) / args.iterations})
        print(f"rbac-warm-control {language}: {median*1e6/args.iterations:.3f} us/op; checksum={args.iterations}", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
