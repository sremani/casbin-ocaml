# Local release review

This closes the current PitBoard for a bounded Casbin OCaml learning port, using OCaml 5.5.x and pinned Go Casbin `524f3f2dc9baef696d748db491d49b3055d359d1`. It is a local release candidate for the declared subset; the [coverage inventory](coverage.md) lists omitted APIs and strict boundaries. GitHub and public package publication remain a later user-requested stage.

## Delivered behavior

The immutable library and string CLI support ACL, basic and exact-domain RBAC, schema-checked typed ABAC, basic keyMatch, allow/deny/combined effects and normal priority effects with stable signed64 numeric ordering. Single-row policy/grouping management and direct role/user queries preserve old snapshots and fail atomically. Applications distinguish an evaluation error from false authorization. Typed ABAC is exposed through the library; the tagged/native probes are verification tools.

Supported behavior was compared against independently observed results from the actual pinned Go library. Explicit boundary expectations check both implementations rather than skipping a Go failure or treating every rejected input as equivalent. Go comma-key identity and textual p_ row selection are preserved. Documented stricter validation, graph consistency and invalid-priority boundaries remain explicit.

## Acceptance evidence

| Gate | Result |
| --- | --- |
| Active toolchain | ocamlc and ocamlopt 5.5.0; Dune 3.1.1 |
| OCaml unit suites | All pass: parser/enforcer/role boundaries; 111 matcher, 111,447 nonpriority effect, 191 management, 244 keyMatch, 166 domain, 206 ABAC and 1,685 priority checks |
| String enforcement corpus | 684 cases: 635 parity and 49 explicit strict rejections; both CLIs checked |
| Management corpus | 53 sequences, 787 steps, 14 explicit boundary traces; both probes checked |
| Native typed ABAC corpus | 270 cases: 246 parity and 24 explicit boundaries; both probes checked |
| Package installation | Declared dune build/runtest -p casbin_ocaml commands and @install pass; scripts/check_package.sh installs to a temporary prefix and compiles/runs an independent consumer plus installed CLI allow/deny/error checks |
| Package metadata | opam lint has no errors; maintainer/authors fields identify project contributors |
| Provenance | Clean pinned source and local Go replacement verified; 30 README-mapped upstream copies, including root/corpus LICENSE/NOTICE pairs, are byte-identical |
| Performance | Nine checked workloads, three samples per implementation, fresh binaries and source/binary hashes; timing/allocation evidence and limitations in performance.md |
| Independent review | PitCrew Intake source/API/coverage review; PitCrew Matcher library/test/install/measurement review; PitCrew Oracle source/corpus/provenance/measurement review; no unresolved blocker |
| Local closure | Feature commits recorded in PITBOARD.md and Git; final release ticket closes through the verified local M8 commit and clean-tree check |

The remaining opam warnings are absent homepage and bug-reports URLs. This project intentionally has no remote; those URLs belong to the later GitHub/publication stage. They are metadata warnings, not build or installation failures.

## Reproduce the gates

```sh
./scripts/verify.sh
./scripts/check_package.sh
opam lint casbin_ocaml.opam
python3 scripts/benchmark.py --output .cache/performance.json
git diff --check
git status --short
```

Verification requires the declared compiler tools plus Git, Go and Python, and can download the pinned public source/modules on its first run. Package metadata lint additionally uses opam. The verification-only benchmark requires a POSIX monotonic clock and C compiler. Timings have no pass/fail speed threshold. Build/test/install do not require a GitHub repository or remote.

The performance report preserves full samples and labels warm Go role memoization, warm filesystem loads, fixed implementation order, immutable versus mutable management, and runtime-specific allocation counters. It makes no whole-library speed claim. The production library continues to use only the OCaml standard library.

Future work requires new scope and tickets. SubjectPriority, other matching functions, eval/reflection/custom functions, named assertions, adapters/watchers/caches, batch/filtered/update management, convenience/implicit queries and multicore/distributed lifecycle are outside this completed board. This review does not claim full Casbin feature parity.
