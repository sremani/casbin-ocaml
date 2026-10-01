#!/usr/bin/env python3
"""Run bounded, independently logged correctness gates in an isolated Luigi workspace."""
import argparse
import datetime
import json
import os
import platform
import subprocess
import time
from pathlib import Path

PIN = "524f3f2dc9baef696d748db491d49b3055d359d1"

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.run_root.resolve()
    project = root / "project"
    results, logs = root / "results", root / "logs"
    results.mkdir(parents=True, exist_ok=True); logs.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(project / "scripts/check_toolchain.sh")], cwd=project, check=True)
    env = os.environ.copy()
    env.update(GOCACHE=str(project / ".cache/go-build"), GOMODCACHE=str(project / ".cache/go-mod"), GOMAXPROCS="8", CGO_ENABLED="1", TMPDIR=str(root / "tmp"))
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    for name in [env["GOCACHE"], env["GOMODCACHE"]]: Path(name).mkdir(parents=True, exist_ok=True)
    def output(command, cwd=project):
        return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()
    source = project / "upstream/casbin"
    if output(["git", "rev-parse", "HEAD"], source) != PIN or output(["git", "status", "--porcelain", "--untracked-files=all"], source):
        raise ValueError("clean pinned upstream required")
    report = {"schema_version":1,"started_utc":utc(),"upstream_revision":PIN,
              "project_revision":output(["git","rev-parse","HEAD"]),
              "project_status_before":output(["git","status","--porcelain"]),
              "machine":{"hostname":platform.node(),"platform":platform.platform(),"affinity":sorted(os.sched_getaffinity(0)),"load_before":os.getloadavg(),
                         "cpuinfo":Path("/proc/cpuinfo").read_text(),"meminfo":Path("/proc/meminfo").read_text()},
              "toolchains":{"ocamlc":output(["ocamlc","-version"]),"ocamlopt":output(["ocamlopt","-version"]),"dune":output(["dune","--version"]),"go":output(["go","version"]),"python":platform.python_version(),"go_env":output(["go","env","-json","GOOS","GOARCH","CGO_ENABLED","CC"])},
              "limits":{"gomaxprocs":8,"go_package_parallelism":8},"stages":[]}
    receipt = results / "gauntlet.json"
    def save(): receipt.write_text(json.dumps(report, indent=2)+"\n")
    def run(name, command, cwd=project, seconds=1200):
        start = time.monotonic(); entry={"name":name,"command":command,"cwd":str(cwd),"started_utc":utc(),"timeout_seconds":seconds}
        stdout, stderr = logs/(name+".stdout"), logs/(name+".stderr")
        entry.update(stdout=str(stdout),stderr=str(stderr),resource_log=str(logs/(name+".resources")))
        with stdout.open("w") as out, stderr.open("w") as err:
            try:
                completed=subprocess.run(["timeout","--signal=TERM","--kill-after=30",str(seconds),"/usr/bin/time","-v","-o",entry["resource_log"],*command],cwd=cwd,env=env,stdout=out,stderr=err)
                entry["exit_code"]=completed.returncode
            except OSError as problem:
                entry["exit_code"]=127; entry["error"]=str(problem)
        entry.update(elapsed_seconds=time.monotonic()-start,finished_utc=utc())
        report["stages"].append(entry);save()
        print(f'{name}: exit={entry["exit_code"]} elapsed={entry["elapsed_seconds"]:.2f}s',flush=True)
        return entry["exit_code"]
    def disposable(name):
        checkout=root/("upstream-tests-"+name)
        if checkout.exists(): raise ValueError("refusing to reuse test checkout: "+str(checkout))
        subprocess.run(["git","clone","--shared","--no-checkout",str(source),str(checkout)],env=env,check=True)
        subprocess.run(["git","-C",str(checkout),"checkout","--detach",PIN],env=env,check=True)
        return checkout
    run("ocaml-compatibility",["./scripts/verify.sh"],seconds=1200)
    run("installed-package",["./scripts/check_package.sh"],seconds=600)
    run("package-release-build",["dune","build","-p","casbin_ocaml","-j","8"],seconds=600)
    run("package-release-tests",["dune","runtest","--force","-p","casbin_ocaml","-j","8"],seconds=600)
    for repeat in range(3):
        run("ocaml-repeat-"+str(repeat),["dune","runtest","--force","--profile","release","-j","8"],seconds=600)
    for name, flags, seconds in [
        ("go-unit",["test","-mod=readonly","-p","8","-count=1","-timeout=15m","-json","./..."],1200),
        ("go-race",["test","-mod=readonly","-p","8","-race","-count=1","-timeout=20m","-json","./..."],1500),
        ("go-vet",["vet","-mod=readonly","-p","8","./..."],600),
        ("go-schedule-stress",["test","-mod=readonly","-p","8","-race","-count=3","-shuffle=on","-timeout=20m","-json","-run","^(TestSync|TestStopAutoLoadPolicy|TestSynced|TestConcurrentTransactions|TestTransaction|TestCachedGFunction)","."],1500),
        ("go-fuzz-inventory",["test","-mod=readonly","-p","8","-list","^Fuzz","./..."],300),
        ("go-benchmark-inventory",["test","-mod=readonly","-p","8","-list","^Benchmark","./..."],300),
        ("go-native-benchmarks",["test","-mod=readonly","-p","8","-run","^$","-bench",".","-benchtime=100ms","-benchmem","-count=3","-timeout=30m","./..."],2100),
    ]:
        checkout=disposable(name)
        run(name,["go",*flags],cwd=checkout,seconds=seconds)
        report["stages"][-1]["checkout_status_after"]=output(["git","status","--porcelain","--untracked-files=all"],checkout)
        save()
    for seed in [42,401,20261001]:
        run("differential-stress-"+str(seed),["python3","scripts/stress_gauntlet.py","--seed",str(seed),"--count","3000","--output",str(results/("stress-"+str(seed)+".json"))],seconds=1200)
    report.update(finished_utc=utc(),upstream_status_after=output(["git","status","--porcelain","--untracked-files=all"],source),project_status_after=output(["git","status","--porcelain"]),load_after=os.getloadavg())
    report["passed"]=all(stage["exit_code"]==0 for stage in report["stages"]) and report["upstream_status_after"]==""
    save()
    raise SystemExit(0 if report["passed"] else 1)

if __name__=="__main__": main()
