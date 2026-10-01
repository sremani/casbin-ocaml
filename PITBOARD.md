# Casbin → OCaml PitBoard

PitBoss: scope, shared interfaces, role manager, enforcer, CLI, documentation, integration.

First finish line: a reproducible ACL/basic RBAC library and CLI with explicit unsupported-feature errors and independent Go oracle comparisons.

Project compiler standard: OCaml 5.5.x (>= 5.5 and < 5.6), selected through the active PATH. The toolchain guard requires both ocamlc and ocamlopt in the 5.5 series; verification runs it before building or accessing the network.

The first few milestones are recorded with local Git commits in the isolated casbin-ocaml repository. PitBoss owns the commits and records each completed, verified milestone on the intended local branch `codex/casbin-ocaml`. PitCrew report completion and verification evidence; they commit only when explicitly assigned. The surrounding workspace must never be committed as part of this project.

Milestone commits are recorded in local Git history. GitHub repository creation and pushing are deferred until the user requests that later stage; this project has no remote for now.

| Crew | Assignment | Owned paths | Status |
| --- | --- | --- | --- |
| PitCrew Intake | Model and policy parsing; matcher/CLI/script review | lib/model.ml, lib/policy.ml, test/parser_test.ml | Complete |
| PitCrew Matcher | Typed matcher compilation/evaluation; enforcer/role review | lib/expr.ml, test/expr_test.ml | Complete |
| PitCrew Oracle | Pinned Go runner, differential corpus, fixture provenance | oracle/, test/fixtures/, scripts/verify_oracle.py | Complete |
| PitBoss | Role manager, enforcer, CLI, package, integration and completion checks | Other files | First milestone complete |

Scope is string-valued requests/policies; equality and Boolean matcher operations; one allow-effect rule; optional two-argument `g`; bounded transitive role membership. ABAC, domains, alternate effect rules, dynamic eval, adapters, watchers, and mutable management APIs are deferred.

Upstream: https://github.com/apache/casbin at 524f3f2dc9baef696d748db491d49b3055d359d1.

## First milestone evidence

- OCaml 5.5.0 builds and OCaml test suites pass.
- Package install artifacts build successfully; `scripts/verify.sh` passes end to end.
- Matcher suite has 111 checks; parser and enforcer/role boundary suites pass.
- Differential corpus: 90 cases, including 73 parity cases and 17 explicit unsupported rejections. Both Go and OCaml expectations pass with OCaml 5.5.0.
- Example: `alice data2 read` on the upstream basic RBAC fixture returns `true`.
- Copied upstream fixtures retain LICENSE/NOTICE and match pinned source bytes.
- Independent crew reviews identified literal-preprocessing, date-typing, role-cycle, duplicate-key and continuation boundaries; fixes or explicit subset restrictions are in place.

## Next work queue

1. PitBoss specifies allow/deny policy-effect extensions and their compatibility cases.
2. PitCrew Intake extends effect/model validation and fixture loading.
3. PitCrew Matcher implements the agreed effect evaluation without widening unrelated matcher syntax.
4. PitCrew Oracle adds independently observed Go decisions and error cases.
5. PitBoss integrates and certifies the extension before expanding scope.

The queue is planning for the next milestone, not a claim that deferred Casbin features have shipped. Detailed syntax and known differences are recorded in README.md and test/fixtures/README.md.
