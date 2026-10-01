#!/usr/bin/env python3
"""Checksum-checked local benchmarks; timings are evidence, not a CI gate."""
import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = "524f3f2dc9baef696d748db491d49b3055d359d1"
BASE_SCENARIOS = ["acl-first", "acl-last", "acl-miss", "rbac", "domain", "abac",
                  "priority", "management", "load"]
EXTRA_SCENARIOS = ["rbac-cold", "keymatch", "deny-override", "allow-and-deny", "priority-first"]
RUNTIME_KEYS = ["OCAMLRUNPARAM", "OCAMLPARAM", "GOGC", "GOMAXPROCS", "GOMEMLIMIT",
                "GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED"]


def model(request, fields, matcher, roles=None, effect="some(where (p.eft == allow))"):
    grouping = "" if roles is None else f"[role_definition]\ng = {roles}\n"
    return (f"[request_definition]\nr = {request}\n[policy_definition]\np = {fields}\n"
            f"{grouping}[policy_effect]\ne = {effect}\n[matchers]\nm = {matcher}\n")


def version(command):
    return subprocess.check_output(command, text=True, cwd=ROOT).strip()


def optional_command(command):
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=5, check=True)
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def optional_file(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def machine_info():
    info = {"system": platform.system(), "machine": platform.machine(),
            "platform": platform.platform(), "uname": platform.uname()._asdict(),
            "cpu_count": os.cpu_count()}
    try:
        info["load_average"] = list(os.getloadavg())
    except (AttributeError, OSError):
        info["load_average"] = None
    try:
        info["affinity_cpus"] = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        info["affinity_cpus"] = None
    cpuinfo = optional_file("/proc/cpuinfo")
    info["cpu_model"] = next((line.split(":", 1)[1].strip() for line in (cpuinfo or "").splitlines()
                              if line.startswith("model name") or line.startswith("Hardware")), None)
    memory = optional_file("/proc/meminfo")
    if memory:
        info["memory_kib"] = {line.split(":", 1)[0]: int(line.split()[1])
                              for line in memory.splitlines()
                              if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))}
    else:
        info["memory_kib"] = None
    try:
        info["physical_memory_bytes"] = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        info["physical_memory_bytes"] = None
    if platform.system() == "Darwin":
        info["cpu_model"] = optional_command(["sysctl", "-n", "machdep.cpu.brand_string"]) or optional_command(["sysctl", "-n", "hw.model"])
        total = optional_command(["sysctl", "-n", "hw.memsize"])
        if total and total.isdecimal():
            info["physical_memory_bytes"] = int(total)
    info["cpu_governor"] = optional_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    info["cgroup_limits"] = {name: optional_file("/sys/fs/cgroup/" + name)
                              for name in ("cpu.max", "memory.max", "memory.current")}
    info["os_release"] = optional_file("/etc/os-release")
    return info


def workload(name, rows, scaled):
    """Construct shared inputs; default rows=100 preserves the original nine."""
    acl = model("sub, obj, act", "sub, obj, act", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
    acl_policy = "".join(f"p, u{i}, data, read\n" for i in range(rows))
    schema = {"sub": "string", "obj": "string", "act": "string"}
    source, policy, verdict, units = acl, acl_policy, True, 1
    shape = {"sub": "u0", "obj": "data", "act": "read"}
    chain_tail = "".join(f"g, role{i}, role{i+1}\n" for i in range(1, 10))
    chain = "g, u0, role1\n" + chain_tail
    count = rows if scaled else 1
    if name in ("acl-last", "priority"):
        shape["sub"] = f"u{rows-1}"
    if name == "acl-miss":
        shape["sub"], verdict = "absent", False
    elif name == "management":
        shape = {"operation": "add then remove", "row": ["temporary", "data", "read"]}
        units = 2
    elif name == "load":
        shape, units = {"operation": "construct from files"}, rows
    elif name in ("rbac", "rbac-cold"):
        source = model("sub, obj, act", "sub, obj, act",
                       "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act", "_, _")
        if name == "rbac-cold":
            policy = "p, role10, data, read\n" + "".join(f"g, u{i}, role1\n" for i in range(rows)) + chain_tail
            shape["sub"] = {"strategy": "unique u0..u(iterations-1)", "cold_role_tuples": True,
                            "expression_warmup_subject": "warmup-unlinked"}
        else:
            policy = "".join(f"p, unrelated{i}, data, read\n" for i in range(count-1)) + "p, role10, data, read\n" + chain
    elif name == "domain":
        source = model("sub, dom, obj, act", "sub, dom, obj, act",
                       "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act", "_, _, _")
        policy = "".join(f"p, unrelated{i}, tenant, data, read\n" for i in range(count-1)) + "p, role10, tenant, data, read\n"
        policy += "".join(line + ", tenant\n" for line in chain.splitlines())
        schema = {"sub": "string", "dom": "string", "obj": "string", "act": "string"}
        shape["dom"] = "tenant"
    elif name == "abac":
        source = model("sub, obj, act", "sub, obj, act", "r.obj.Owner == r.sub && r.obj.Age >= 18 && r.act == p.act")
        policy = "".join(f"p, unused{i}, unused, write\n" for i in range(count-1)) + "p, unused, unused, read\n"
        schema["obj"] = {"object": {"Owner": "string", "Age": "number"}}
        shape = {"sub": "alice", "obj": {"Owner": "alice", "Age": 42.0}, "act": "read"}
    elif name == "priority":
        source = model("sub, obj, act", "priority, sub, obj, act, eft",
                       "r.sub == p.sub && r.obj == p.obj && r.act == p.act", effect="priority(p.eft) || deny")
        policy = "".join(f"p, {i}, u{i}, data, read, allow\n" for i in reversed(range(rows)))
    elif name == "keymatch":
        source = model("sub, obj, act", "sub, obj, act",
                       "keyMatch(r.obj, p.obj) && r.act == p.act && r.sub == p.sub")
        policy = "".join(f"p, u{i}, /segment{i}/*, read\n" for i in range(rows))
        shape = {"sub": f"u{rows-1}", "obj": f"/segment{rows-1}/item", "act": "read"}
    elif name in ("deny-override", "allow-and-deny", "priority-first"):
        effect = {"deny-override": "!some(where (p.eft == deny))",
                  "allow-and-deny": "some(where (p.eft == allow)) && !some(where (p.eft == deny))",
                  "priority-first": "priority(p.eft) || deny"}[name]
        source = model("sub, obj, act", "sub, obj, act, eft", "r.obj == p.obj && r.act == p.act", effect=effect)
        policy = "".join(f"p, u{i}, data, read, {'deny' if i == rows-1 else 'allow'}\n" for i in range(rows))
        shape["sub"] = "alice"
        verdict = name == "priority-first" and rows > 1
    elif name not in BASE_SCENARIOS:
        raise ValueError("unknown scenario: " + name)
    return {"model": source, "policy": policy, "schema": schema, "request": shape,
            "checksum_per_iteration": units if verdict else 0,
            "policy_rows": sum(line.startswith("p,") for line in policy.splitlines()),
            "grouping_rows": sum(line.startswith("g,") for line in policy.splitlines())}


def parse_result(result, name, iterations, expected):
    fields = result.stdout.rstrip("\n").split("\t")
    if (result.returncode != 0 or result.stderr or result.stdout != "\t".join(fields) + "\n"
            or len(fields) != 5 or fields[0] != name or int(fields[1]) != iterations or int(fields[3]) != expected):
        raise ValueError(f"invalid benchmark result: {result}")
    elapsed, allocated = float(fields[2]), float(fields[4])
    if not 0 < elapsed < float("inf") or not 0 <= allocated < float("inf"):
        raise ValueError("invalid measured duration/allocation count")
    return elapsed, allocated


def runtime_info(binary, environment):
    result = subprocess.run([str(binary), "--runtime-info"], env=environment, capture_output=True,
                            text=True, check=True, timeout=10)
    if result.stderr:
        raise ValueError("runtime-info must not write stderr: " + result.stderr)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".cache/performance.json")
    parser.add_argument("--iterations", type=int, default=5000, help="maximum operations per sample")
    parser.add_argument("--repeats", type=int, default=5)
    size_options = parser.add_mutually_exclusive_group()
    size_options.add_argument("--rows", type=int, default=100)
    size_options.add_argument("--sizes", help="comma-separated positive row counts; enables expanded workloads")
    size_options.add_argument("--matrix", action="store_true", help="expanded workloads at 10,100,1000,10000 rows")
    parser.add_argument("--profile", choices=["release", "dev"], default="release")
    parser.add_argument("--scan-budget", type=int, default=500000, help="bound policy rows times operations per sample, with a minimum of one operation")
    parser.add_argument("--scenarios", help="comma-separated scenario filter")
    parser.add_argument("--build-dir", default="_build", help="Dune build directory (private directories supported)")
    parser.add_argument("--ocaml-runparam", help="subprocess-only OCAMLRUNPARAM experiment")
    parser.add_argument("--gogc", help="subprocess-only GOGC experiment")
    parser.add_argument("--gomaxprocs", type=int, help="subprocess-only GOMAXPROCS experiment")
    parser.add_argument("--gomemlimit", help="subprocess-only GOMEMLIMIT experiment")
    args = parser.parse_args()
    if args.iterations <= 0 or args.rows <= 0 or args.scan_budget <= 0 or args.repeats < 5:
        parser.error("iterations, rows and scan-budget must be positive; repeats must be at least five")
    if args.gomaxprocs is not None and args.gomaxprocs <= 0:
        parser.error("gomaxprocs must be positive")
    try:
        sizes = [int(value) for value in args.sizes.split(",")] if args.sizes is not None else ([10, 100, 1000, 10000] if args.matrix else [args.rows])
    except ValueError:
        parser.error("sizes must be comma-separated integers")
    if any(size <= 0 for size in sizes) or len(set(sizes)) != len(sizes):
        parser.error("sizes must be positive and distinct")
    expanded = bool(args.matrix or args.sizes is not None)
    names = BASE_SCENARIOS + (EXTRA_SCENARIOS if expanded else [])
    if args.scenarios:
        names = args.scenarios.split(",")
        if any(name not in BASE_SCENARIOS + EXTRA_SCENARIOS for name in names) or len(set(names)) != len(names):
            parser.error("scenarios must be distinct supported names")
    subprocess.run([str(ROOT / "scripts/check_toolchain.sh")], check=True)
    if (version(["git", "-C", str(ROOT / "upstream/casbin"), "rev-parse", "HEAD"]) != PIN
            or version(["git", "-C", str(ROOT / "upstream/casbin"), "status", "--porcelain", "--untracked-files=all"])):
        raise ValueError("benchmark requires the clean pinned source")
    if "replace github.com/casbin/casbin/v3 => ../upstream/casbin" not in (ROOT / "oracle/go.mod").read_text():
        raise ValueError("benchmark oracle must use the pinned local replacement")
    dune_command = ["dune", "build", "--profile", args.profile, "--build-dir", args.build_dir, "bin/benchmark.exe"]
    subprocess.run(dune_command, cwd=ROOT, check=True)
    build_environment = os.environ.copy()
    for key, name in [("GOCACHE", "go-build"), ("GOMODCACHE", "go-mod")]:
        directory = ROOT / ".cache" / name
        directory.mkdir(parents=True, exist_ok=True)
        build_environment[key] = str(directory)
    go_binary = ROOT / ".cache" / ("casbin-benchmark-" + args.profile)
    go_command = ["go", "build", "-mod=readonly"]
    if args.profile == "dev":
        go_command += ["-gcflags=all=-N -l"]
    go_command += ["-o", str(go_binary), "./benchmark"]
    subprocess.run(go_command, cwd=ROOT / "oracle", env=build_environment, check=True)
    binaries = {"ocaml": ROOT / args.build_dir / "default/bin/benchmark.exe", "go": go_binary}
    environment = os.environ.copy()
    for key, value in [("OCAMLRUNPARAM", args.ocaml_runparam), ("GOGC", args.gogc),
                       ("GOMAXPROCS", args.gomaxprocs), ("GOMEMLIMIT", args.gomemlimit)]:
        if value is not None:
            environment[key] = str(value)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    text_digest = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    paths = list((ROOT / "lib").glob("*.ml")) + list((ROOT / "lib").glob("*.mli"))
    paths += [ROOT / name for name in ["bin/benchmark.ml", "bin/benchmark_clock.c", "scripts/benchmark.py", "oracle/benchmark/main.go", "lib/dune", "bin/dune", "dune-project", "oracle/go.mod", "oracle/go.sum"]]
    report = {"schema_version": 2, "captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "upstream_commit": PIN, "profile": args.profile, "machine": machine_info(),
              "versions": {"ocamlc": version(["ocamlc", "-version"]), "ocamlopt": version(["ocamlopt", "-version"]),
                           "dune": version(["dune", "--version"]), "go": version(["go", "version"])},
              "repeats": args.repeats, "sizes": sizes, "expanded_workloads": expanded,
              "requested_iterations": args.iterations, "scan_budget": args.scan_budget,
              "scan_budget_basis": "policy rows times logical operations; management operation is an add/remove pair; minimum one operation",
              "sample_order": "ocaml,go on even repeat indexes; go,ocaml on odd repeat indexes",
              "runtime": {"inherited_flags": {key: os.environ.get(key) for key in RUNTIME_KEYS},
                          "effective_flags": {key: environment.get(key) for key in RUNTIME_KEYS},
                          "baseline": {name: runtime_info(binary, os.environ.copy()) for name, binary in binaries.items()},
                          "effective": {name: runtime_info(binary, environment) for name, binary in binaries.items()}},
              "provenance": {"project_revision": version(["git", "rev-parse", "HEAD"]),
                             "project_status": version(["git", "status", "--porcelain"]),
                             "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)},
                             "binary_sha256": {name: digest(path) for name, path in binaries.items()},
                             "command": [sys.executable, *sys.argv], "build_commands": [dune_command, go_command]},
              "results": []}
    with tempfile.TemporaryDirectory(prefix="casbin-benchmark-") as temporary:
        directory = Path(temporary)
        for rows in sizes:
            for name in names:
                data = workload(name, rows, expanded or rows != 100)
                visits = max(1, data["policy_rows"])
                if name == "load":
                    requested = max(20, args.iterations // 50)
                else:
                    requested = args.iterations
                iterations = max(1, min(requested, args.scan_budget // visits))
                if name == "rbac-cold":
                    iterations = min(iterations, rows)
                warmup = 1 if name == "rbac-cold" else min(100, max(1, 500000 // rows))
                expected = data["checksum_per_iteration"] * iterations
                model_file, policy_file = directory / f"{name}-{rows}.conf", directory / f"{name}-{rows}.csv"
                model_file.write_text(data["model"])
                policy_file.write_text(data["policy"])
                samples = {language: [] for language in binaries}
                allocations = {language: [] for language in binaries}
                orders = []
                for repeat in range(args.repeats):
                    order = ["ocaml", "go"] if repeat % 2 == 0 else ["go", "ocaml"]
                    orders.append(order)
                    for language in order:
                        result = subprocess.run([str(binaries[language]), name, str(model_file), str(policy_file), str(iterations), str(rows)],
                                                env=environment, capture_output=True, text=True, timeout=120)
                        elapsed, allocated = parse_result(result, name, iterations, expected)
                        samples[language].append(elapsed)
                        allocations[language].append(allocated)
                input_hashes = {"model_sha256": text_digest(data["model"]), "policy_sha256": text_digest(data["policy"]),
                                "schema_sha256": text_digest(json.dumps(data["schema"], sort_keys=True, separators=(",", ":"))),
                                "request_sha256": text_digest(json.dumps(data["request"], sort_keys=True, separators=(",", ":")))}
                for language in binaries:
                    median = statistics.median(samples[language])
                    report["results"].append({"scenario": name, "language": language, "rows": rows,
                        "policy_rows": data["policy_rows"], "grouping_rows": data["grouping_rows"],
                        "schema": data["schema"], "request": data["request"], "input_sha256": input_hashes,
                        "iterations": iterations, "warmup_operations": warmup, "checksum": expected,
                        "sample_order": orders, "seconds": samples[language], "allocated_bytes": allocations[language],
                        "median_allocated_bytes_per_operation": statistics.median(allocations[language]) / iterations,
                        "median_seconds": median, "median_us_per_operation": median * 1e6 / iterations})
                    print(f"{name:15s} rows={rows:5d} {language:5s} {median*1e6/iterations:10.3f} us/op; checksum={expected}", flush=True)
    report["machine_after"] = machine_info()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
