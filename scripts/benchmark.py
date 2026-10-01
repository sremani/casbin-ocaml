#!/usr/bin/env python3
"""Reproducible, checksum-checked local evidence; timings are not a CI gate."""
import argparse
import json
import hashlib
import os
import sys
import platform
import statistics
import subprocess
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
PIN = "524f3f2dc9baef696d748db491d49b3055d359d1"

def model(request, fields, matcher, roles=None, effect="some(where (p.eft == allow))"):
    grouping = "" if roles is None else f"[role_definition]\ng = {roles}\n"
    return (f"[request_definition]\nr = {request}\n[policy_definition]\np = {fields}\n"
            f"{grouping}[policy_effect]\ne = {effect}\n[matchers]\nm = {matcher}\n")

def version(command):
    return subprocess.check_output(command, text=True, cwd=ROOT).strip()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".cache/performance.json")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.iterations <= 0 or args.repeats <= 0:
        parser.error("iterations and repeats must be positive")
    subprocess.run([str(ROOT / "scripts/check_toolchain.sh")], check=True)
    pin = version(["git", "-C", str(ROOT / "upstream/casbin"), "rev-parse", "HEAD"])
    if pin != PIN or version(["git", "-C", str(ROOT / "upstream/casbin"), "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("benchmark requires the clean pinned source")
    module = (ROOT / "oracle/go.mod").read_text()
    if "replace github.com/casbin/casbin/v3 => ../upstream/casbin" not in module:
        raise ValueError("benchmark oracle must use the pinned local replacement")
    subprocess.run(["dune", "build", "bin/benchmark.exe"], cwd=ROOT, check=True)
    build_environment = os.environ.copy()
    for key, name in [("GOCACHE", "go-build"), ("GOMODCACHE", "go-mod")]:
        directory = ROOT / ".cache" / name
        directory.mkdir(parents=True, exist_ok=True)
        build_environment[key] = str(directory)
    subprocess.run(["go", "build", "-mod=readonly", "-o", "casbin-benchmark", "./benchmark"],
                   cwd=ROOT / "oracle", env=build_environment, check=True)
    acl = model("sub, obj, act", "sub, obj, act", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
    acl_policy = "".join(f"p, u{i}, data, read\n" for i in range(100))
    rbac = model("sub, obj, act", "sub, obj, act", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act", "_, _")
    chain = "g, u0, role1\n" + "".join(f"g, role{i}, role{i+1}\n" for i in range(1,10))
    domain = model("sub, dom, obj, act", "sub, dom, obj, act", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act", "_, _, _")
    domain_policy = "p, role10, tenant, data, read\n" + "".join(line.rstrip()+", tenant\n" for line in chain.splitlines())
    abac = model("sub, obj, act", "sub, obj, act", "r.obj.Owner == r.sub && r.obj.Age >= 18 && r.act == p.act")
    priority = model("sub, obj, act", "priority, sub, obj, act, eft", "r.sub == p.sub && r.obj == p.obj && r.act == p.act", effect="priority(p.eft) || deny")
    priority_policy = "".join(f"p, {i}, u{i}, data, read, allow\n" for i in reversed(range(100)))
    scenarios = [(name, acl, acl_policy, args.iterations, 0 if name == "acl-miss" else args.iterations)
                 for name in ["acl-first", "acl-last", "acl-miss"]]
    scenarios += [("rbac", rbac, "p, role10, data, read\n"+chain, args.iterations, args.iterations),
                  ("domain", domain, domain_policy, args.iterations, args.iterations),
                  ("abac", abac, "p, unused, unused, read\n", args.iterations, args.iterations),
                  ("priority", priority, priority_policy, args.iterations, args.iterations),
                  ("management", acl, acl_policy, args.iterations, 2*args.iterations),
                  ("load", acl, acl_policy, max(20,args.iterations//50), 100*max(20,args.iterations//50))]
    binaries = {"ocaml": ROOT / "_build/default/bin/benchmark.exe", "go": ROOT / "oracle/casbin-benchmark"}
    report = {"schema_version":1,"upstream_commit":PIN,
              "machine":{"system":platform.system(),"machine":platform.machine(),"platform":platform.platform()},
              "versions":{"ocamlc":version(["ocamlc","-version"]),"ocamlopt":version(["ocamlopt","-version"]),"dune":version(["dune","--version"]),"go":version(["go","version"])},
              "repeats":args.repeats,"warmup_operations":100,"results":[]}
    paths = list((ROOT / "lib").glob("*.ml")) + list((ROOT / "lib").glob("*.mli"))
    paths += [ROOT / name for name in ["bin/benchmark.ml", "bin/benchmark_clock.c", "scripts/benchmark.py", "oracle/benchmark/main.go", "lib/dune", "bin/dune", "dune-project", "oracle/go.mod", "oracle/go.sum"]]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["provenance"] = {"project_revision":version(["git", "rev-parse", "HEAD"]),
                            "project_status":version(["git", "status", "--porcelain"]),
                            "source_sha256":{str(p.relative_to(ROOT)):digest(p) for p in sorted(paths)},
                            "binary_sha256":{name:digest(path) for name,path in binaries.items()},
                            "command":[sys.executable,*sys.argv],
                            "build_commands":[["dune","build","bin/benchmark.exe"],["go","build","-mod=readonly","-o","casbin-benchmark","./benchmark"]]}
    with tempfile.TemporaryDirectory(prefix="casbin-benchmark-") as temporary:
        directory = Path(temporary)
        for name, source, policy, iterations, expected in scenarios:
            model_file, policy_file = directory / (name+".conf"), directory / (name+".csv")
            model_file.write_text(source); policy_file.write_text(policy)
            for language, binary in binaries.items():
                samples = []
                allocations = []
                for _ in range(args.repeats):
                    result = subprocess.run([str(binary),name,str(model_file),str(policy_file),str(iterations)],
                                            capture_output=True,text=True,check=True,timeout=60)
                    fields = result.stdout.rstrip("\n").split("\t")
                    if result.stderr or result.stdout != "\t".join(fields)+"\n" or len(fields)!=5 or fields[0]!=name or int(fields[1])!=iterations or int(fields[3])!=expected:
                        raise ValueError(f"invalid benchmark result: {result}")
                    elapsed = float(fields[2])
                    if not 0 < elapsed < float("inf"):
                        raise ValueError("invalid measured duration")
                    samples.append(elapsed)
                    allocated = float(fields[4])
                    if not 0 <= allocated < float("inf"):
                        raise ValueError("invalid allocation count")
                    allocations.append(allocated)
                median = statistics.median(samples)
                report["results"].append({"scenario":name,"language":language,"iterations":iterations,"checksum":expected,
                                          "seconds":samples,"allocated_bytes":allocations,"median_allocated_bytes_per_operation":statistics.median(allocations)/iterations,
                                          "median_seconds":median,"median_us_per_operation":median*1e6/iterations})
                print(f"{name:12s} {language:5s} {median*1e6/iterations:10.3f} us/op; checksum={expected}")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")

if __name__=="__main__":
    main()
