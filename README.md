# Casbin → OCaml

An OCaml learning port of a bounded ACL, basic/exact-domain RBAC and typed ABAC subset of Apache Casbin (Incubating). PitBoss coordinates the design, integration, and verification; PitCrew members implement assigned components. The project board is [PITBOARD.md](PITBOARD.md).

The implemented core is an immutable library and command-line enforcer, checked against Go Casbin at commit `524f3f2dc9baef696d748db491d49b3055d359d1`. The library uses only the OCaml standard library. PitBoss drives tickets and verification gates from PITBOARD.md and commits completed milestones locally.

## Build and use

Requirements: OCaml 5.5.x (>= 5.5 and < 5.6) and Dune 3.1 or later. The package allows 5.5 patch releases. Full differential verification additionally requires Git, Go 1.20 or later, and Python 3.9 or later. Public upstream source and Go dependencies are downloaded on the first verification run.

Commands use the compiler tools on the active `PATH`. Select the intended OCaml 5.5 toolchain for the current session, then run `scripts/check_toolchain.sh`; it requires both `ocamlc` and `ocamlopt` to report a `5.5.*` version. `scripts/verify.sh` runs the guard before any build or network operation. Project verification targets OCaml 5.5 only; toolchain selection requires no global installation or removal.

```sh
./scripts/check_toolchain.sh
dune build @all
dune runtest
dune exec casbin-ocaml -- test/fixtures/rbac_model.conf test/fixtures/rbac_policy.csv alice data2 read
# true
./scripts/verify.sh
```

The CLI accepts `MODEL.conf POLICY.csv REQUEST_FIELD...` and prints exactly `true` or `false`. Both decisions exit successfully. Invalid input, unsupported features, and I/O failures print a diagnostic to stderr and exit 2. Applications must keep an evaluation error distinct from an authorization decision.

The library API exposes a validated snapshot:

```ocaml
match Casbin.Enforcer.of_files ~model:"model.conf" ~policy:"policy.csv" with
| Error message -> Error message
| Ok enforcer -> Casbin.Enforcer.enforce enforcer ["alice"; "data2"; "read"]
```

`Enforcer.of_strings` supports in-memory model and policy text. The number of request arguments is determined by the declared request fields. Snapshots are immutable; management operations return a new snapshot and a changed flag. Adopt the returned snapshot to use the update; earlier snapshots remain valid.

```ocaml
match Casbin.Enforcer.add_policy enforcer ["bob"; "data2"; "read"] with
| Error message -> Error message
| Ok (updated, changed) ->
    Casbin.Enforcer.enforce updated ["bob"; "data2"; "read"]
```

Policy and two-argument grouping operations support get, has, add and remove, plus direct roles for a user and users for a role. No-ops return the original snapshot and false. Invalid policy arities and newly inserted cyclic role graphs fail atomically. See the [management contract](docs/management-contract.md) for validation, operation traces and explicit differences from raw Go mutation behavior.

Typed ABAC snapshots use `of_strings_abac` or `of_files_abac` with a schema for every declared request field, followed by `enforce_values`:

```ocaml
let request_schema = [
  "sub", Casbin.Value.TString;
  "obj", Casbin.Value.TObject ["Owner", Casbin.Value.TString];
  "act", Casbin.Value.TString;
] in
match Casbin.Enforcer.of_files_abac ~request_schema ~model:"abac.conf" ~policy:"policy.csv" with
| Error message -> Error message
| Ok enforcer -> Casbin.Enforcer.enforce_values enforcer [
    Casbin.Value.String "alice";
    Casbin.Value.Object ["Owner", Casbin.Value.String "alice"];
    Casbin.Value.String "read";
  ]
```

For a matcher such as `r.sub == r.obj.Owner`, object attributes are checked against the schema before evaluation. Typed snapshots support same-type scalar equality, numeric/string ordering, Boolean logic, roles, domains and keyMatch. Whole-request validation rejects missing, extra or duplicate properties, type mismatches and nonfinite numbers, including unused fields. The legacy constructors still accept only strings. See the [ABAC contract](docs/abac-contract.md) for grammar, schema boundaries and Go comparisons.

The local package is `casbin_ocaml`; applications link it with `(libraries casbin_ocaml)` and use the `Casbin` module. `dune build @install` prepares the library and `casbin-ocaml` executable for installation. Package metadata is included in `casbin_ocaml.opam`.

## Compatibility contract

| Surface | Implemented contract |
| --- | --- |
| Model | One `r`, `p`, `e`, `m`; optional `g = _, _` or domain `g = _, _, _` |
| Values | Legacy strings, or schema-checked typed request strings, float64 numbers, booleans and objects; policy fields remain strings |
| Matchers | Legacy string equality and Boolean logic; typed ABAC adds nested attributes and scalar comparisons; declared `g` and `keyMatch` |
| Policy effect | Allow override, deny override, combined allow-and-deny, and first-decision priority; optional explicit `p.eft` at any position |
| Role graph | Self membership, directed transitive membership, at most ten edges; cyclic/self-edge policies rejected at load |
| Policy input | Physical-line CSV; quoted commas/doubled quotes; comments and duplicate records |
| Model input | Whitespace/comments and backslash line continuation within the declared subset |
| Management | Immutable policy/grouping get, has, add, remove; exact-domain variants; direct role/user queries |
| Errors | Unsupported models/functions/fields, malformed input, wrong arity, missing files |

An empty policy is evaluated using an empty-string policy row, matching Go Casbin. A matcher independent of policy fields is evaluated once unless its text contains `p_`. Go uses that textual marker even inside a string literal or request attribute name; populated policies then supply the effects. This means `m = true` allows even without policy records; absence of records alone is not a guarantee of denial.

Supported effect rules are:

| Expression | Decision |
| --- | --- |
| `some(where (p.eft == allow))` | Allow if any matching row allows |
| `!some(where (p.eft == deny))` | Allow unless a matching row denies, including when no rows match |
| `some(where (p.eft == allow)) && !some(where (p.eft == deny))` | Require a matching allow and no matching deny |
| `priority(p.eft) \|\| deny` | First matched determinate allow/deny in policy order; default deny |

Without an `eft` policy field, matching rows implicitly allow. Explicit values are case-sensitive: `allow` and `deny` have their named effects; other values, including empty strings, are indeterminate. The synthetic row used for empty policies or request-only matchers follows upstream's special effect behavior: a false synthetic matcher still allows under deny override. The differential corpus covers these cases.

Priority effects use the first matching row whose effect is `allow` or `deny`, skipping unmatched and indeterminate rows. Without a field named `priority`, file/append order applies. A `priority` field at any position stably orders rows by ascending signed64 decimal value for every supported effect; additions insert after numeric ties. Leading zeroes and `+`/`-` signs preserve raw duplicate identities. Invalid stored priorities fail atomically, a stricter boundary than Go's invalid-value ordering. See the [priority contract](docs/priority-contract.md).

Quoted matcher strings preserve literal backslashes. Literal contents containing either quote character, brackets, `#`, `:`, assertion-like `r`/`p` prefixes followed by optional digits and a dot, or a `YYYY-MM-DD` shaped substring are excluded. These restrictions avoid Go preprocessing and implicit date conversion; ordinary literals such as `'alice'` are supported. Arbitrary dates, quotes, Unicode, and backslashes remain usable as request/policy field values.

Strict validation rejects unknown policy types and unsupported definitions. The differential corpus records accepted behavior and deliberate rejection cases. Compatibility applies to the declared subset and pinned upstream revision.

Input whitespace support is ASCII. Unicode whitespace trimming and Go's file-scanner line-size cap are not reproduced. The model parser normalizes whitespace within the supported effect expression and rejects duplicate sections, definitions, fields, and dangling or interrupted backslash continuations. These validation choices are deliberate differences from upstream.

Duplicate policy and role keys use comma-joined field values, reproducing Go Casbin's key behavior. Distinct quoted field tuples can collide; the first row is retained. For example, `p, "a,b", c, read` and `p, a, "b,c", read` share a duplicate key. The oracle corpus covers the resulting decisions.

Domain RBAC uses `g(subject, role, domain)` with exact byte-string domains. Graphs are isolated by domain, including the empty domain; implicit self membership and the ten-edge bound apply within each graph. The application matcher supplies domain equality when permission rows must share the request domain. Domain tuple mutations and `~domain` direct role queries preserve immutable snapshots. Unscoped direct queries use the empty domain. Newly stored self edges and cycles fail atomically; domain cycles also fail at load, an explicit difference from the pinned Go detector. Models that activate upstream automatic domain `keyMatch` registration are rejected. See the [domain contract](docs/domain-contract.md).

`keyMatch(key, pattern)` compares strings exactly when the pattern has no `*`. With a star it requires the byte prefix before the first star, which may match zero remaining bytes; later pattern text is ignored. `/foo*` matches `/foo` and `/foobar`, while `/foo/*` requires `/foo/`. No path normalization, regex or escaping is applied. See the [keyMatch contract](docs/key-match-contract.md).

Deferred: subject-priority and custom effect rules, multiple assertions, domain patterns, reflection, numeric coercion, `eval`, regex and other path-matching functions, custom functions, adapters, watchers, caching, filtered/batch/update management operations, and the full Casbin public API.

## Verification and provenance

`scripts/verify.sh` first checks the active OCaml 5.5 compiler tools, checks the pinned clean upstream checkout, builds both implementations, runs OCaml boundary tests, then runs the enforcement, management and native typed ABAC differential corpora. It fails on an unsupported toolchain, mismatched verdicts, unexpected errors, or missing inputs. `scripts/prepare_upstream.sh` restores a fresh pinned source checkout if needed and refuses to certify an existing modified checkout. A changed upstream revision requires reviewing the contract and regenerating evidence.

The Go oracle is an independent runner around the actual upstream library, not a second implementation of the OCaml logic. Fixtures include upstream examples and custom cases; see [fixture provenance](test/fixtures/README.md). Unit tests cover parser failures, matcher typing/precedence, request errors, and role-depth boundaries.

Copied upstream material retains Apache license and notice files. This is an independent learning project; the name describes its source compatibility target. See [LICENSE](LICENSE), [NOTICE](NOTICE), and the project’s compatibility limitations above.

## Local release evidence

The current board delivers the bounded feature set above. See the [coverage inventory](docs/coverage.md), [measured performance](docs/performance.md) and [release review](docs/release-review.md) for implementation mapping, deferred API families and acceptance evidence. `scripts/check_package.sh` builds and installs into a temporary prefix, then tests an independent consumer and the installed CLI; `examples/installed_consumer.ml` is the checked usage example.

Performance evidence is reproduced with `python3 scripts/benchmark.py` after preparing the pinned source. The benchmark requires a POSIX monotonic clock and C compiler; it adds no production-library dependency. Timings are workload evidence rather than pass/fail speed targets.

The [Luigi gauntlet](docs/luigi-gauntlet.md) adds seeded differential stress, full upstream tests and race checks, and a release benchmark matrix (`python3 scripts/benchmark.py --matrix --profile release`). See the [completed Luigi benchmarks and test report](docs/luigi/2026-10-01/README.md).

Local commits record completed milestones. GitHub, public package publication and future feature extensions remain later user-requested work; each extension gets a new contract and comparison cases.
