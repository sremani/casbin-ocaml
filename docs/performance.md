# Local performance evidence

Measured on 2026-10-01 on macOS-26.6.2-arm64-arm-64bit-Mach-O. OCaml 5.5.0, Dune 3.1.1 and go version go1.27.0 darwin/arm64. The machine architecture is arm64. These are local workload measurements, not a general ranking or a performance guarantee.

The [raw evidence](performance-evidence.json) retains all three timing and allocation samples for each of 18 results, exact tool versions, the clean upstream pin, source/binary SHA-256 hashes, invocation/build commands and project revision/status. The measured library comes from M7 `c079470`; benchmark/metadata/documentation files were pending M8 changes, explicitly captured as a working-tree measurement.

Reproduce from this repository:

```sh
./scripts/check_toolchain.sh
./scripts/prepare_upstream.sh
python3 scripts/benchmark.py --output .cache/performance.json
```

The driver verifies the clean pinned upstream and local Go module replacement, then rebuilds both benchmark binaries before measurement. OCaml uses Dune’s default development profile; Go uses standard go build settings, as captured in the exact commands. The verification-only OCaml benchmark uses a small POSIX monotonic-clock C stub; the production library retains its standard-library-only dependency contract. The Go benchmark uses monotonic elapsed time. A C compiler and POSIX monotonic clock are required for the benchmark.

## Workloads and method

Each scenario constructs identical model/policy/request data for both implementations. Construction and request setup occur outside enforcement timing. There are 100 warmup operations followed by a forced GC, then 5,000 measured operations per repetition (100 for file loading). Workload-triggered GC remains included. All OCaml samples precede all Go samples within a scenario; this fixed order and shared-machine activity limit comparisons.

The runner checks exact output/exit/stderr, scenario, iteration count, expected checksum and finite durations/allocations. Management restores and checks exact ordered baseline rows outside timing. Every workload passed its checksum on every repetition.

| Workload | Data and logical operation |
| --- | --- |
| ACL first/last/miss | 100 permission rows; respectively first matching user, last matching user, or absent user |
| RBAC | One permission row and a ten-edge role chain; repeated identical request |
| Domain | One permission row and a ten-edge exact-domain role chain; repeated identical request |
| ABAC | One permission row; native Owner string and finite Age number, owner equality and numeric threshold |
| Priority | 100 rows loaded in reverse numeric order; request matches the last ascending-priority row |
| Management | 100-row ACL snapshot; one successful add/remove pair returns to baseline |
| Load | Construct from model/policy files with 100 permission rows after filesystem-cache warmup |

Default Go matcher-expression and g-function memo caches are warm; repeated RBAC/domain measurements include Go memo lookup while OCaml evaluates its graph without that cache. These rows do not measure comparable cold graph traversal. File loading measures warm-cache reading, parsing and construction, not cold disk startup. Go management mutates an enforcer; OCaml produces persistent snapshots and preserves old state.

## Observed medians

Times are microseconds per logical operation; management is per add/remove pair and load per complete construction. Allocations are bytes allocated per operation, not retained heap or RSS. OCaml uses Gc.allocated_bytes and Go uses runtime.MemStats.TotalAlloc; runtime representations/counters differ, so these are implementation-specific allocation observations.

| Workload | OCaml µs | Go µs | OCaml allocated bytes | Go allocated bytes |
| --- | ---: | ---: | ---: | ---: |
| acl-first | 0.575 | 2.893 | 1760.0 | 3240.1 |
| acl-last | 18.716 | 18.727 | 99968.0 | 12838.1 |
| acl-miss | 18.744 | 18.022 | 102280.0 | 12813.5 |
| rbac | 1.818 | 2.159 | 7304.0 | 1615.7 |
| domain | 2.222 | 2.708 | 7736.0 | 1743.5 |
| abac | 1.169 | 2.228 | 5256.0 | 1488.1 |
| priority | 27.037 | 23.091 | 127968.0 | 12860.3 |
| management | 11.338 | 0.441 | 12760.0 | 296.0 |
| load | 59.490 | 148.761 | 73241.3 | 492220.5 |

At this size, last-row ACL and miss scans have similar median elapsed times. Early matches and typed owner checks show different costs from complete scans. Immutable OCaml add/remove pairs cost substantially more than Go mutation, and OCaml full scans allocate many per-row bindings. These observations identify potential future work on request/policy binding allocation and persistent policy indexes; no optimization or general throughput claim is implied by this evidence.

The harness and evidence passed independent PitCrew Matcher and Oracle review. Timings are evidence, not a CI threshold; a repeated run is required only when the workload, code or measurement conditions change.
