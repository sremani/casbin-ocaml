# Luigi: correctness and benchmarks, 2026-10-01

All 17 correctness/inventory/native-benchmark stages passed. The declared port corpus and 9,000 seeded differential cases passed with zero mismatches. The paired release matrix and both follow-up controls also exited zero; 826 paired/control samples passed their checksum checks. Production library code is unchanged from M8 `ac5f546`.

Luigi: two Intel Xeon E5-2695 v3 sockets, 28 physical cores / 56 logical CPUs, 125.8 GiB RAM, Linux 6.8.0-138-generic. Paired latency measurements use CPU 2 only, OCaml 5.5.0, Dune 3.24.2 and Go 1.22.2, optimized release builds, default GC settings and Go GOMAXPROCS=1. Native upstream benchmarks use GOMAXPROCS=8 and the full host affinity. These are workload measurements on a shared host, not maximum server throughput or a general language ranking.

Measured project revision: `b013d40d48614a7dd627e30ea7a9291ef2a8295b`. Reference Casbin: `524f3f2dc9baef696d748db491d49b3055d359d1`. Both measured source trees were clean before and after the run.

## Correctness gauntlet

| Gate | Result |
| --- | --- |
| OCaml native tests | Parser/enforcer/role suites; 111 expression, 111,447 exhaustive effect, 191 management, 244 keyMatch, 166 domain, 206 ABAC and 1,685 priority checks passed |
| Fixed enforcement corpus | 684 cases: 635 parity, 49 expected strict rejections |
| Fixed management corpus | 53 sequences / 787 operation steps, including 14 explicit boundary traces |
| Fixed typed ABAC corpus | 270 cases: 246 parity, 24 explicit boundaries |
| Package/repeat gates | Installed consumer/CLI, release package build/test and three forced release test repeats passed |
| Upstream Go unit and race | Each passed 272 top-level tests + 30 subtests across 8 tested packages; 7 packages have no tests |
| Upstream vet and shuffled race | Vet passed; 29 tests + 3 subtests each passed three shuffled race-enabled repetitions |
| Upstream native benchmarks | 56 functions expanded to 58 result names; 174 samples, all exits zero |
| Seeded differential stress | Seeds 42/401/20261001: 9,000 cases, 31,045 management steps, matching expected/Go/OCaml checksums, all 837 eligible anchors covered |
| Upstream fuzz inventory | N/A: no Fuzz targets exist at the pinned revision |

The Go suites run in separate disposable checkouts because tests rewrite policy fixtures. All Go stderr logs were empty. Maximum recorded RSS was about 228 MiB for race testing and 213 MiB for native benchmarks. Stress is conservative metamorphic expansion of supported anchors; it does not prove support for arbitrary Casbin models or deferred API families.

## Paired release matrix

Each cell is **OCaml / Go µs per logical operation**, median of seven alternating-order samples. Construction is excluded except for load. Management is one append/remove pair; load is complete file parsing and enforcer construction with warm filesystem caches. RBAC/domain/ABAC and other scans scale permission rows. Cold RBAC scales identities with **one permission row** and a ten-edge role chain; its absolute latency should not be compared to the many-permission warmed RBAC scan.

| Workload | 10 rows | 100 rows | 1,000 rows | 10,000 rows |
| --- | ---: | ---: | ---: | ---: |
| acl-first | 0.912 / 4.682 | 0.912 / 5.047 | 1.042 / 9.148 | 0.906 / 109.892 |
| acl-last | 3.821 / 8.984 | 32.754 / 52.108 | 332.605 / 493.066 | 4,101.087 / 5,307.339 |
| acl-miss | 3.437 / 8.550 | 33.455 / 51.600 | 355.109 / 489.414 | 4,228.027 / 5,281.605 |
| rbac | 23.755 / 12.061 | 235.742 / 79.550 | 2,387.769 / 776.938 | 23,966.055 / 9,044.193 |
| domain | 26.039 / 15.594 | 251.221 / 106.459 | 2,523.069 / 1,071.668 | 25,443.954 / 12,071.834 |
| abac | 10.976 / 15.165 | 104.082 / 115.417 | 1,080.658 / 1,124.394 | 11,267.677 / 11,981.479 |
| priority | 5.021 / 9.200 | 43.964 / 60.640 | 459.280 / 1,159.169 | 5,357.004 / 70,078.176 |
| management | 1.986 / 1.118 | 16.506 / 1.073 | 185.327 / 1.010 | 2,178.450 / 1.018 |
| load | 20.375 / 78.629 | 60.602 / 321.254 | 659.174 / 3,172.446 | 10,432.419 / 47,685.352 |
| rbac-cold | 7.203 / 12.257 | 7.836 / 9.762 | 4.148 / 8.155 | 4.367 / 12.310 |
| keymatch | 4.733 / 10.524 | 41.881 / 65.580 | 437.651 / 627.907 | 5,079.545 / 6,853.289 |
| deny-override | 6.173 / 10.306 | 60.240 / 74.410 | 619.601 / 723.921 | 6,875.187 / 7,775.351 |
| allow-and-deny | 6.136 / 10.453 | 60.419 / 75.026 | 620.983 / 733.283 | 6,934.361 / 7,801.479 |
| priority-first | 0.825 / 3.993 | 0.808 / 4.521 | 0.879 / 9.675 | 0.762 / 118.991 |

The main matrix requested up to 100,000 operations and capped logical policy-row visits at 5,000,000 per sample. Exact counts and raw timing/allocation arrays are in [paired-release.json](paired-release.json). This budget does not cap internal effector work. At 10,000 rows, ordinary full-scan samples lasted seconds with low variation; fast OCaml first-match and Go mutation samples were below 1 ms. Go mutation at 10,000 rows had roughly 10.2% sample coefficient of variation, so interpret its result as approximately 1 µs rather than a precise speed ratio.

## Longer first-match samples

These separate runs use 100,000 operations per sample at 10,000 rows, the same source/binaries/runtime settings and seven repetitions. Longer batches change GC/runtime amortization as well as timing precision; retain both receipts rather than combining their raw samples.

| Workload | OCaml µs | Go µs |
| --- | ---: | ---: |
| acl-first | 0.926 | 75.807 |
| priority-first | 0.785 | 89.436 |

Raw evidence: [paired-first-match.json](paired-first-match.json). The Go first-match path still allocates policy-sized effect/match buffers; the OCaml path returns after the first decisive row without those buffers.

## Same-graph request-reuse control

Both cases use identical model/policy/schema hashes, one permission row and 10,000 identities. Fresh tuples use 10,000 unique subjects and an expression-only sentinel warmup; repeated requests use `u0`, 50 warmups and 100,000 measured calls. Each has seven samples. This changes request reuse, working-set locality and subject-formatting cost together, so it is not a pure isolated cache ablation.

| Requests | OCaml µs | Go µs |
| --- | ---: | ---: |
| Fresh subject/role tuples | 4.367 | 12.310 |
| Repeated `u0` tuple | 4.102 | 7.152 |

The control verified the main receipt SHA, exact binaries, complete source fingerprints, compiler versions, clean revision and effective runtime configuration before measurement. [role-cache-control.json](role-cache-control.json) records all checks and samples.

## Allocation observations at 10,000 rows

Median managed bytes allocated per logical operation. OCaml uses `Gc.allocated_bytes`; Go uses `MemStats.TotalAlloc`. These are runtime-specific allocation counters, not equivalent object accounting, retained heap or peak RSS.

| Workload | OCaml bytes/op | Go bytes/op |
| --- | ---: | ---: |
| acl-last | 9,920,768.3 | 1,125,170.6 |
| rbac | 67,520,552.3 | 1,917,266.4 |
| domain | 69,680,768.3 | 2,805,377.8 |
| abac | 34,961,760.3 | 1,765,163.4 |
| priority | 12,720,768.3 | 1,125,246.0 |
| management | 1,200,760.3 | 296.0 |
| load | 6,401,920.3 | 47,527,464.2 |
| rbac-cold | 7,360.0 | 1,806.8 |

## Interpretation

- Full ACL scans, keyMatch, effect scans and file construction favor this OCaml implementation in these measurements. Typed ABAC is close. Warmed many-permission RBAC/domain scans favor Go; its generated `g()` function memoizes tuple results while the OCaml implementation traverses the graph.
- Pinned Go normal priority reverse-scans the entire effect buffer after each evaluated row: only-last-match enforcement performs N(N−1)+1 merge-slot checks. At 10,000 rows that is 99,990,001 checks per enforcement, versus streaming outcomes in OCaml. The measured 70.08 ms / 5.36 ms difference is about 13.1× for this specific workload, with identical supported verdicts.
- OCaml immutable append/remove snapshots copy and validate policy state; Go mutates an indexed enforcer and removes the just-appended final row. The large update gap reflects different state/operation contracts and this particular row position, not a universal mutation ranking.
- The main OCaml opportunities suggested by source inspection and measured allocation are per-row request/policy bindings, repeated role traversal and persistent policy indexes. These are future optimization candidates; this run makes no production optimization changes.

## Native upstream benchmark selection

These use upstream models, cache types and APIs rather than the paired fixtures. Several native benchmarks discard enforcement errors, mix mutation with noops or have costly setup/initial misses. Their successful execution is separately recorded; do not compare their names directly with the paired OCaml rows.

| Native Go benchmark | Median µs/op | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkBasicModel | 6.8330 | 1,482 | 16 |
| BenchmarkRBACModel | 10.1460 | 2,060 | 34 |
| BenchmarkABACModel | 4.9790 | 1,511 | 16 |
| BenchmarkKeyMatchModel | 8.1010 | 1,667 | 20 |
| BenchmarkPriorityModel | 7.4850 | 1,749 | 21 |
| BenchmarkCachedBasicModel | 0.3343 | 104 | 4 |
| BenchmarkCachedRBACModel | 0.3584 | 104 | 4 |

Benchmark calculations, variation and 529 audit assertions: [benchmark-summary.json](benchmark-summary.json). Full native samples, method and caveats: [go-native-summary.json](go-native-summary.json). Correctness/vet/race audits: [go-summary.json](go-summary.json). Stress assertions and log hashes: [stress-summary.json](stress-summary.json). Full stage receipt: [gauntlet.json](gauntlet.json).

## Reproduction and evidence

See [the run method](../../luigi-gauntlet.md) for exact commands and controls. The isolated remote root is `/home/srikanth/casbin-ocaml-luigi-20261001-ac5f546`. Toolchain source tags/revisions: OCaml `5.5.0` / `f5238509da6029a44ba0eb648f5dff7d9c89f519`; Dune `3.24.2` / `ce734ac25ffb06994a4530426bb06ee8cda19e50`. Dune was built with its official `dune-bootstrap` profile after ordinary package builds reported missing external libraries; the successful isolated build/install commands are retained in `logs/toolchain-success.log`.

The complete execution archive is retained locally at `.cache/luigi/evidence/luigi-evidence.tar.gz` and under the remote root; it is not included in the GitHub checkout. It contains every stdout/stderr/resource log, all 9,000 complete JSONL case records, receipts, launch scripts and the control driver. Archive SHA-256: `a91baddef5ecca194169a0ab49ebbacfce250c31f22ef451bf30cc621e65487c`. The archive is intentionally kept outside version control; committed receipts and summaries bind its evidence hashes. Source repositories and toolchains were neither published nor installed globally.
