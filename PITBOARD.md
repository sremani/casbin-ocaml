# Casbin → OCaml PitBoard

PitBoss: scope, shared interfaces, role manager, enforcer, CLI, documentation, integration.

PitBoss drives this board proactively: dispatch ready tickets, review evidence, integrate, verify, commit the milestone, then select the next ready wave. Statuses are Backlog, Ready, In progress, Review, and Done. Done requires the ticket's acceptance gate; a local commit closes a milestone.

Project compiler standard: OCaml 5.5.x (>= 5.5 and < 5.6), selected through the active PATH. The toolchain guard requires both ocamlc and ocamlopt in the 5.5 series; verification runs it before building or accessing the network.

The first few milestones are recorded with local Git commits in the isolated casbin-ocaml repository. PitBoss owns the commits and records each completed, verified milestone on the intended local branch `codex/casbin-ocaml`. PitCrew report completion and verification evidence; they commit only when explicitly assigned. The surrounding workspace must never be committed as part of this project.

Milestone commits are recorded in local Git history. GitHub repository creation and pushing are deferred until the user requests that later stage; this project has no remote for now.

## M2 — policy effects

| Ticket | Work and acceptance gate | Owner | Depends on | Status |
| --- | --- | --- | --- | --- |
| CB-001 | ACL/basic RBAC core, package and 90-case corpus; local commit `e4f3b34` | PitBoss + crew | — | Done |
| CB-101 | Parse three supported effect forms and optional `p.eft`; strict parser boundaries pass | PitCrew Intake | — | Done |
| CB-102 | Aggregate allow/deny/indeterminate effects; exhaustive small truth tables pass | PitCrew Matcher | — | Done |
| CB-103 | Independently observed Go effect corpus, including synthetic rows and mixed effects | PitCrew Oracle | — | Done |
| CB-104 | Integrate effects in enforcer, preserving short-circuit and empty-policy semantics | PitBoss | CB-101, CB-102 | Done |
| CB-105 | Cross-review, OCaml 5.5 tests, 317-case corpus and install build pass | PitBoss + crew | CB-101–104 | Done |
| CB-106 | Document effect contract and record verified M2 local commit; see local Git history | PitBoss | CB-105 | Done |

M2 supports allow override, deny override, and allow-and-deny. Missing `eft` means allow; unknown explicit effects are indeterminate. Priority, subject-priority, and arbitrary effect languages remain separate scope decisions.

## M3 — immutable policy management

| Ticket | Work and acceptance gate | Owner | Depends on | Status |
| --- | --- | --- | --- | --- |
| CB-201 | Immutable API and operation-trace contract in docs/management-contract.md | PitBoss | CB-106 | Done |
| CB-202 | Add/remove policy and role links; duplicate/no-op semantics; snapshot remains valid | PitCrew Intake | CB-201 | Done |
| CB-203 | 191 management regression and snapshot-isolation checks pass | PitCrew Matcher | CB-201 | Done |
| CB-204 | Go operation-sequence oracle: 23 cases, 261 steps, seven explicit boundaries | PitCrew Oracle | CB-201 | Done |
| CB-205 | Integrate management, check error atomicity and role-cycle rejection; all gates pass | PitBoss + crew | CB-202–204 | Done |
| CB-206 | Document and locally commit M3; see local Git history | PitBoss | CB-205 | Done |

## M4 — basic keyMatch

| Ticket | Work and acceptance gate | Owner | Depends on | Status |
| --- | --- | --- | --- | --- |
| CB-301 | Specify basic keyMatch extension in docs/key-match-contract.md | PitBoss | CB-206 | Done |
| CB-311 | Implement two-string keyMatch compilation/evaluation and policy dependencies | PitCrew Intake | CB-301 | Done |
| CB-312 | 244 byte, typing, short-circuit and snapshot integration checks pass | PitCrew Matcher | CB-301 | Done |
| CB-313 | 116 observed keyMatch cases and three management traces; provenance recorded | PitCrew Oracle | CB-301 | Done |
| CB-314 | Integrate, cross-review, verify all corpora and install build | PitBoss + crew | CB-311–313 | Done |
| CB-315 | Document and locally commit M4; see local Git history | PitBoss | CB-314 | Done |

## Prioritized backlog

| Ticket | Work and acceptance gate | Owner | Depends on | Status |
| --- | --- | --- | --- | --- |
| CB-302 | Implement exact-domain RBAC, immutable domain management and golden cases | PitBoss + crew | CB-315 | Done |
| CB-321 | Domain model/policy parsing and three-string g expressions | PitCrew Intake | CB-302 contract | Done |
| CB-322 | 166 domain semantic, parser and snapshot checks pass | PitCrew Matcher | CB-302 contract | Done |
| CB-323 | Independently observed domain enforcement/management Go corpus | PitCrew Oracle | CB-302 contract | Done |
| CB-324 | Domain graph/enforcer integration, strict atomic management, full gates and local commit | PitBoss | CB-321–323 | Done |
| CB-303 | Implement schema-checked typed ABAC values and enforcement | PitBoss + crew | CB-324 | Done |
| CB-331 | Compile/evaluate nested typed attributes and scalar comparisons | PitCrew Intake | CB-303 contract | Done |
| CB-332 | Immutable Value/schema validation and ABAC regression suite | PitCrew Matcher | CB-303 contract | Done |
| CB-333 | Native Go typed-request oracle, corpus and strict boundary traces | PitCrew Oracle | CB-303 contract | Done |
| CB-334 | Typed Enforcer/probe integration, cross-review, full gates and local commit | PitBoss | CB-331–333 | Done |
| CB-304 | Priority-effect semantics and policy-order tests | PitBoss + crew | CB-206 | Backlog |
| CB-401 | Port coverage inventory, performance evidence, release-quality review | PitBoss + crew | Feature scope selected | Backlog |

The current contract supports legacy string requests and schema-checked typed ABAC requests; policies remain strings within the documented matcher subset. Each extension gets scoped acceptance criteria before dispatch; backlog entries are not claims of implemented parity.

Upstream: https://github.com/apache/casbin at 524f3f2dc9baef696d748db491d49b3055d359d1.

## First milestone evidence

- OCaml 5.5.0 builds and OCaml test suites pass.
- Package install artifacts build successfully; `scripts/verify.sh` passes end to end.
- Matcher suite has 111 checks; parser and enforcer/role boundary suites pass.
- Differential corpus: 90 cases, including 73 parity cases and 17 explicit unsupported rejections. Both Go and OCaml expectations pass with OCaml 5.5.0.
- Example: `alice data2 read` on the upstream basic RBAC fixture returns `true`.
- Copied upstream fixtures retain LICENSE/NOTICE and match pinned source bytes.
- Independent crew reviews identified literal-preprocessing, date-typing, role-cycle, duplicate-key and continuation boundaries; fixes or explicit subset restrictions are in place.

## Decision log

- PitBoss manages ticket selection and crew coordination without waiting for the user to repeat permission at each checkpoint.
- Build and oracle evidence precede a local milestone commit. GitHub remains a later user-requested stage.
- Compatibility follows pinned Go behavior where declared; unsupported features produce errors. Detailed syntax and differences live in README.md and test/fixtures/README.md.
- M2 gate: 317 corpus cases pass (293 parity, 24 explicit rejections), 111,447 exhaustive effect checks plus parser/matcher/enforcer tests, install build and cross-review pass. M3 is the next dispatched wave.
- M2 local commit: `1b68831`. M3 uses immutable snapshots and preserves the original on failed updates; raw Go mutation cycle/arity behavior is recorded as an explicit boundary rather than silently emulated.

- M3 gate: 191 stateful checks, 317 enforcement cases, and 23 management sequences (261 steps, seven explicit boundaries) pass on OCaml 5.5.0. Install build and independent management/API/runner reviews pass. Immutable snapshots retain previous state on invalid updates.

- M3 local commit: `ba5e10a`. M4 implements only basic `keyMatch`; its first-asterisk byte-prefix contract was fixed before dispatch.

- M4 gate: 244 keyMatch checks plus all existing suites pass. Enforcement corpus: 433 cases (406 parity, 27 explicit rejections); management: 26 sequences, 313 steps, seven explicit boundaries. OCaml 5.5.0, install build and independent source/implementation/test cross-review pass. Next selected ticket is CB-302: scope domains before implementation.

- M5 gate: 166 domain checks and all prior suites pass on OCaml 5.5.0. Enforcement: 511 cases (474 parity, 37 explicit rejections); management: 37 sequences, 444 steps, 13 explicit boundaries including Go NUL cache-key collisions. Package build, provenance and crew implementation/test reviews pass. Exact-domain feature and immutable management are implemented; ABAC is next.

- M5 local commit: `a0cca07`. M6 implements schema-checked ABAC through explicit typed constructors and a separate matcher compiler, preserving legacy string callers.

- M6 gate: 206 ABAC API/value/schema/compiler/snapshot checks and all prior suites pass on OCaml 5.5.0. Enforcement: 511 cases (474 parity, 37 rejections); management: 37 sequences, 444 steps, 13 boundaries; native ABAC: 214 cases (193 parity, 21 boundaries). Install build and independent source/API/probe reviews pass. Go textual p_ row selection is reproduced, including literals and attributes; full validation differences are explicit. Next wave is CB-304 priority effects and stable numeric ordering.
