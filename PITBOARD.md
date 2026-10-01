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

## Active wave: M3 — immutable policy management

| Ticket | Work and acceptance gate | Owner | Depends on | Status |
| --- | --- | --- | --- | --- |
| CB-201 | Specify immutable policy/role-management API and observable Go contract | PitBoss | CB-106 | In progress |
| CB-202 | Add/remove policy and role links; duplicate/no-op semantics; snapshot remains valid | PitCrew Intake | CB-201 | Ready |
| CB-203 | Management regression and snapshot-isolation tests | PitCrew Matcher | CB-201 | Ready |
| CB-204 | Go operation-sequence oracle and management corpus | PitCrew Oracle | CB-201 | Ready |
| CB-205 | Integrate management, check error atomicity and role-cycle rejection; all gates pass | PitBoss + crew | CB-202–204 | Backlog |
| CB-206 | Document and locally commit M3 | PitBoss | CB-205 | Backlog |
| CB-301 | Specify a small matching-function extension, then implement and compare to Go | PitBoss + crew | CB-206 | Backlog |
| CB-302 | Domain-aware RBAC contract and golden cases | PitBoss + crew | CB-206 | Backlog |
| CB-303 | Explicit OCaml ABAC value model and supported evaluation boundary | PitBoss + crew | CB-206 | Backlog |
| CB-304 | Priority-effect semantics and policy-order tests | PitBoss + crew | CB-206 | Backlog |
| CB-401 | Port coverage inventory, performance evidence, release-quality review | PitBoss + crew | Feature scope selected | Backlog |

The current contract remains string-valued requests/policies and the documented matcher subset. Each extension gets scoped acceptance criteria before dispatch; backlog entries are not claims of implemented parity.

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
