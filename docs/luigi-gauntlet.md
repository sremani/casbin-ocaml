# Luigi test gauntlet

This run compares the declared Casbin-OCaml subset with Go Casbin pinned at
`524f3f2dc9baef696d748db491d49b3055d359d1`. Production OCaml library code is
unchanged from milestone M8 (`ac5f546`); M9 adds test and measurement harnesses.
Both sources and the OCaml 5.5.0/Dune 3.24.2 toolchain live under one isolated
Luigi run directory. Go uses Luigi's installed compiler. No GitHub publication
or global toolchain changes are part of this run.

## Correctness

`python3 scripts/luigi_gauntlet.py --run-root /absolute/run/directory` expects
the project at `project/` and the selected toolchain on PATH. It records machine
metadata, compiler versions, revisions, commands, exit codes, wall time, timeout
limits and separate stdout/stderr/resource logs. Each upstream Go stage uses a
fresh detached checkout: upstream tests intentionally rewrite tracked fixtures.
The canonical pinned checkout must remain clean.

The gates include the full port compatibility corpus, installed package/CLI,
release package build/tests, three forced OCaml test repetitions, upstream Go
unit tests, race detector, vet, shuffled repeated concurrency/transaction tests,
fuzz/benchmark inventories, and all native Go benchmarks with three bounded
samples. An empty fuzz inventory means upstream has no fuzz targets; it is not
a fuzzing pass. Native Go benchmarks cover upstream features beyond this port
and are separate evidence from the paired comparison.

Three differential stress seeds (42, 401, 20261001) each generate 3,000 cases
from supported corpus anchors. The generator checks each implementation against
the anchor's independently recorded expected output, including complete
management traces. Conservative transformations exercise renamed identities,
duplicate rows, safe permutations, priority offsets and typed numeric scaling.
This is seeded metamorphic testing, not arbitrary matcher fuzzing or a proof of
compatibility outside the declared subset. Strict boundaries remain covered by
the full baseline corpus. A failure stops that stress seed, retaining its model,
policy, complete input and replay command. Every generated case has a JSONL
record. Use `scripts/stress_gauntlet.py --replay /absolute/failure/case.json`
with the same six prebuilt probes to reproduce it.

## Paired performance

`scripts/benchmark.py` defaults to release builds; `--profile dev` selects Dune
dev and disables Go compiler optimization/inlining. Legacy nine-scenario input
shapes remain available without `--matrix`. The release matrix adds cold RBAC,
keyMatch, deny override, combined allow/deny and first-match priority, scaling
across 10, 100, 1,000 and 10,000 policy/identity rows.

Example single-CPU comparison on Linux:

```sh
taskset -c 2 python3 scripts/benchmark.py --matrix --profile release \
  --iterations 100000 --scan-budget 5000000 --repeats 7 --gomaxprocs 1 \
  --output /absolute/run/directory/results/paired-release.json
```

Both implementations receive identical generated inputs, are measured inside
their processes with monotonic clocks, alternate order across repetitions, and
must return exact checksums. Timings exclude construction except in the `load`
scenario. Load operations include file parsing and full enforcer construction.
Allocation totals are each runtime's reported managed allocation, not RSS or
directly equivalent accounting. Repeated RBAC exercises Go's warmed role cache;
`rbac-cold` compiles the expression with an unrelated sentinel first, then uses
fresh role tuples. Cold samples at small identity counts have few operations
and should be interpreted cautiously.

The receipt records actual iteration counts, raw samples, medians, workload
hashes, compiler/runtime settings, machine load/affinity and source/binary
hashes. The scan budget bounds expensive cases; it is not a latency guarantee.
It counts logical row visits, not internal effector work: pinned Go normal
priority scans the full effect buffer after each evaluated row. With only the
last row matching, that produces N(N−1)+1 merge-slot checks. The OCaml effector
streams ordered outcomes. This is an implementation cost difference for the
measured workload, rather than a general language claim.
GC flags are opt-in per-process experiments and must be reported separately
from default-runtime measurements. Luigi is a shared host: CPU pinning reduces
scheduling variation but does not eliminate shared-cache or memory interference.
Timings are evidence rather than pass/fail speed targets. M8's earlier local
performance receipt remains historical and separate.

The focused first-match receipt uses 100,000 operations at 10,000 rows because
the matrix's row budget yields very short OCaml first-match samples. A separate
`scripts/role_cache_benchmark.py` control verifies and reuses the matrix binaries,
source hashes and runtime settings. It holds the cold-role model, one permission
row and 10,000-identity graph constant while measuring repeated `u0` requests.
The original cold case measures fresh subject/role tuples; formatting those
subjects also occurs inside its timer. This control changes request reuse and
that formatting cost together, so it is not a pure isolated cache ablation.

The completed [Luigi results](luigi/2026-10-01/README.md) include the full matrix,
controls, correctness audits, raw receipts and evidence archive manifest.
