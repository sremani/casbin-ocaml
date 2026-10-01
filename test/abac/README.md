# Typed ABAC differential corpus

Reference: [Apache Casbin](https://github.com/apache/casbin), clean pinned commit
`524f3f2dc9baef696d748db491d49b3055d359d1`.

The corpus contains 270 cases: 246 parity cases and 24 explicit stricter
boundaries. Every Go expectation was independently observed through
`oracle/casbin-abac-oracle`, which unmarshals a JSON array into native Go
strings, float64 numbers, booleans, maps, arrays, and nulls, then calls the real
`Enforce` API. It does not enable JSON reinterpretation of opaque strings.

## Provenance

`owner-upstream.conf` was copied byte-for-byte from upstream
`examples/abac_model.conf`. LICENSE and NOTICE were copied byte-for-byte from the
pinned upstream root and apply to that example. All other models, policies,
manifest cases, and this documentation were authored for this port. Authored
fixtures are based on the declared typed contract, with actual Go results
recorded rather than inferred or skipped.

## Coverage

Owner and nested properties are maps with case-sensitive keys; a lowercase map
property is supported without Go struct export/reflection heuristics. Schema
field order and object property order are independent of model/request order.
The scalar matrix exercises all six comparison operators for numbers and
strings, boolean equality/inequality/logic, negative and fractional values,
signed zero, very small/large finite values, float64 rounding around 2^53,
Unicode/string-byte ordering, and embedded NUL/control strings.

Matcher numeric literals use unsigned or negative decimal notation, including
`.5`, `1.`, and whitespace after the minus (`- .5`, `- 1`). JSON request numbers
may use scientific notation. Pinned Go rejects scientific and explicit-plus
matcher numeric syntax; its hex numeric literals are an explicit unsupported
OCaml boundary. An overflowing native JSON number is rejected on both sides.
Comparison operators share precedence and associate left: numeric/string
ordering can feed boolean equality, and chained boolean equality is checked
against Go.

Composition cases combine nested string accessors with two-/three-argument
role calls, exact domains, keyMatch, string-valued policy fields, and all four
supported effects. Both request-only and policy-dependent empty-policy
synthetic-row behavior are exercised, including empty nested strings and
implicit role self membership.

Strict cases cover missing/extra schema fields and object properties, invalid
property names, incorrect primitive values, wrong request arity, unknown nested
paths, object/mixed-type comparisons, unsupported arrays/nulls, and arithmetic.
A whole request is validated even if Go's short circuit would skip the bad
value or property. Duplicate keys cannot be represented by the manifest's
native JSON dictionaries; duplicate schema/value associations are covered by
OCaml API unit tests rather than silently collapsed golden cases.

Opaque JSON-looking strings remain strings. They can compare as strings, while
an Owner accessor applied to such a string errors; the oracle never converts
one into a map automatically.

## Protocol and exact checks

Each manifest case supplies a model, policy, a `request_schema` dictionary, and
native JSON `request` array. Schema primitives are `string`, `number`, and
`bool`; nested dictionaries describe objects. The runner encodes the OCaml
schema/request using the tab-separated tagged protocol in
`docs/abac-contract.md`: s/hex, n/decimal, b/true-or-false, and o/count/property
pairs. Arrays use a/count and null uses z only to exercise rejection. Empty
strings have empty hex tokens; embedded NUL/tab/newline bytes cannot break token
or line boundaries.

`expected` is the typed OCaml verdict or `"error"`. When Go's dynamic behavior
differs, `oracle_expected` records its independently observed result and
`boundary` explains the stricter rule. Both binaries are always checked. A
successful verdict requires exit 0, empty stderr, and exactly a Boolean plus
newline. An error requires exit 2, empty stdout, and nonempty stderr. The runner
validates the clean source pin, local module replacement, path containment,
unique case names, and complete expectations; no permissive skipping exists.

Build the Go probe with the existing module cache:

```sh
project_dir=$(pwd)
(cd oracle && GOCACHE="$project_dir/.cache/go-build" GOMODCACHE="$project_dir/.cache/go-mod" go build -mod=readonly -o casbin-abac-oracle ./abac)
python3 scripts/verify_abac.py
```

The first build may download the already pinned public Go modules. Use
`./scripts/verify.sh` for the full project gates. `--ocaml`, `--oracle`, and
`--manifest` overrides permit controlled local verification while requiring
both probes.

Go's policy-row selector is textual: a matcher containing `p_` anywhere selects
real policy rows when rows exist, including `p_sub` inside a quoted literal or
as a request object's property name. These two cases return false with a
populated explicit-Deny policy and true with no policy. An ordinary
request-only Owner comparison lacking `p_` still uses the synthetic Allow row
and returns true despite a populated Deny policy. Six parity controls preserve
this source behavior alongside actual AST policy dependencies.


## Milestone 7 typed priority composition

56 new expectations were observed independently with the native Go oracle.
All priority models and policies here were authored for this port; the domain
policy reuses this port's authored enforcement fixture, not an upstream copy.
Owner, finite numeric score, and Boolean activity properties combine with all
four effects, signed64 priority limits, stable equal ranks, signed zero,
unknown effects, and unmatched earlier rules. Implicit row order, missing eft,
request-only and empty-policy synthetic rows, and the textual p_ selector are
also checked under the normal priority effect.

Nested subject/domain/object properties compose with exact-domain roles,
implicit self membership, object keyMatch, embedded NUL in a path, and numeric
and Boolean conditions. Three retained malformed numeric priorities are explicit
strict load boundaries: padded decimal, hexadecimal, and signed64 overflow.
Their native Go Allow verdicts and OCaml load errors are both checked. The
priority restrictions apply to policy fields without narrowing typed request
numbers or ordinary string values.
