# Management operation trace corpus

Reference: [Apache Casbin](https://github.com/apache/casbin), unmodified commit
`524f3f2dc9baef696d748db491d49b3055d359d1`. The Go probe calls actual management
and enforcement APIs with autosave disabled. Each case initializes a fresh
model/policy, then executes its complete operation sequence in one process.

The corpus contains 37 cases, 444 operation steps, and 13 explicit boundary
traces. Three cases require initialization failure rather than an operation
trace. The remaining cases cover duplicate/no-op flags, exact policy/grouping
row order, additions/removals, enforcement after mutation, transitive role
changes, sorted direct role/user queries, all three supported effect
aggregations, comma-key collisions, request-only matchers, empty strings,
Unicode, and embedded tab/newline/comma values.

## Provenance

`basic.conf`, `basic.csv`, `rbac.conf`, and `rbac.csv` are byte-identical copies of
upstream `examples/basic_model.conf`, `examples/basic_policy.csv`,
`examples/rbac_model.conf`, and `examples/rbac_policy.csv` respectively.
`LICENSE` and `NOTICE` were copied byte-for-byte from the pinned upstream root.
Other models, policies, the manifest, and this README were authored for this
port. The effect and request-only models reuse this port's authored milestone 2
fixtures from `test/fixtures`; they were not copied from upstream.

## Trace format and verification

See `docs/management-contract.md` for the fixed protocol. Each manifest operation
has an `op` and string `args`; the runner converts arguments to hexadecimal
UTF-8, separated by tabs. Empty strings become empty hex arguments. The output
is one ASCII line per operation: Boolean, `rows\tHEX,...;HEX,...`,
`values\tHEX,...`, or `error`. Field/row separators cannot collide with encoded
commas, tabs, newlines, or Unicode bytes. Role/user query results are sorted by
byte-string order on both probes. Empty policy/group queries produce `rows\t`;
empty role/user queries produce `values\t`.

`expected` records the complete OCaml output trace. Ordinarily it equals the
independently observed Go trace. Deliberately stricter boundaries use an
explicit `oracle_expected` trace and a written `boundary` explanation. The
runner checks every output line from both drivers against its own expected
trace, exit 0, empty stderr, and the final newline. Operation errors continue
the trace; no operation or Go failure is skipped. Initialization-error cases
require exit 2, empty stdout, and nonempty stderr from both probes.

Run `python3 scripts/verify_management.py` after building both probes, or run
`./scripts/verify.sh` for all gates. The runner validates the clean pinned
upstream and local module replacement before any driver checks. Override
`--ocaml`, `--oracle`, or `--manifest` for controlled local verification; both
probes remain mandatory.

## Explicit boundaries

1. **Grouping collision removal:** Go removes a stored row by comma-joined key,
   but removes the caller's tuple from its incremental role cache. A different
   key-colliding tuple can therefore leave the removed stored edge active in
   role queries and enforcement. OCaml rebuilds the role graph from remaining
   stored rows, keeping rows, queries, and decisions consistent. The trace
   verifies both divergent states and subsequent convergence after exact
   re-add/remove operations.
2. **Short policy row:** Go accepts a two-field `p` add for a three-field model,
   exposes it in queries, and errors on later enforcement. OCaml rejects the
   add/query/remove arity immediately and preserves its previous snapshot.
3. **Oversized policy row:** Go stores four fields for a three-field model and
   fails later enforcement. OCaml rejects before mutation.
4. **Short grouping row:** Go returns an error while adding a one-field `g`
   rule, yet retains the malformed stored row. A later removal also errors
   after removing the row. OCaml rejects these calls before changing state.
5. **Oversized grouping row:** Go stores a three-field `g` rule but builds the
   role link using its first two fields. OCaml requires exactly two fields and
   preserves the prior graph.
6. **Directed role cycle:** Raw Go in-memory mutation accepts a cycle. OCaml
   validates the candidate graph and rejects atomically. Later queries and
   enforcement prove the original valid snapshot remains active.
7. **Explicit self edge:** Raw Go mutation stores a self link. OCaml rejects
   it, retaining implicit self membership for enforcement without creating a
   direct stored/query row.

The `duplicate-before-self-cycle-validation` case is parity: a self tuple whose
comma key already exists under a distinct valid tuple is a no-op. Duplicate
identity must be checked before candidate graph validation. The no-role model
case confirms all grouping and direct role/user APIs return errors, while
ordinary policy APIs and enforcement remain usable.

## Milestone 4 pattern management

`keymatch.conf`, `keymatch-effects.conf`, and `keymatch-rbac.conf` were authored
for this port using its milestone 4 models from `test/fixtures`; they are not
upstream copies. Three additional observed Go traces contain 52 operation
steps. Pattern additions/removals change subsequent enforcement, duplicate
pattern adds are no-ops, explicit allow/deny pattern rules combine correctly,
and role link additions/removals control pattern permissions. Unicode prefixes
are exercised through role-based patterns.

The control-value trace adds a policy pattern containing embedded NUL, tab,
and newline bytes, then queries, matches, duplicates, and removes it. These
values travel through the hex stdin protocol because an ordinary command argv
cannot carry embedded NUL. The first-star suffix remains ignored and the prefix
bytes must match exactly. All three new management traces require complete Go
and OCaml parity; no new management exceptions were introduced.

## Milestone 5 domain management

Ten new domain traces add 113 operation steps. `domain-example.conf` and
`domain-example.csv` were copied byte-for-byte from upstream
`examples/rbac_with_domains_model.conf` and
`examples/rbac_with_domains_policy.csv`; the existing copied LICENSE and NOTICE
apply. Other domain policies were authored for this port.

Generic grouping operations now accept the declared pair or domain triple.
`get_roles_for_user_in_domain` and `get_users_for_role_in_domain` take name and
domain arguments. The Go driver uses the upstream variadic query APIs, which
preserve errors, rather than convenience wrappers that discard errors.
Unscoped queries in a domain model query the default empty-string domain.

Parity traces cover upstream data, direct versus transitive membership,
independent domains, empty domains, sorted queries, generic triple row order,
duplicate-before-self-validation no-ops, and embedded NUL/tab/newline plus
Unicode domain strings transported through hex stdin.

Five additional explicit boundary traces cover same-domain cycle rejection
while accepting opposing edges in separate domains; atomic self-edge
rejection; cross-domain comma-key collision removal and stale upstream role
cache; wrong two-field operations against a three-field grouping declaration;
and explicit domain queries against a two-field model (Go ignores the supplied
domain, while the typed OCaml domain API rejects the model). Queries on a model
without any role declaration error on both sides. All divergent post-error
snapshots, later queries, and enforcement results are checked in full.

A sixth domain boundary trace adds 18 steps for the pinned Go g-function memo
key's NUL delimiter collision. Distinct tuples `(a\0b, c, d)` and
`(a, b\0c, d)` share a memo key when raw values contain NUL. The first matched
row has an unknown effect, while the key-colliding second row has Allow but no
actual role link. Go incorrectly reuses true membership and grants; OCaml's
exact graph denies. The trace checks actual role/policy queries, the divergent
decisions, and later convergence after removing the original link and adding
or removing the correct second link. The source model was authored for this
port; `empty.csv` is also port-authored. This exception is explicitly recorded
in the full Go and OCaml traces, and no cached incorrect grant is emulated.
