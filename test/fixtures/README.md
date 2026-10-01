# Differential fixture corpus

Reference: [Apache Casbin](https://github.com/apache/casbin), pinned commit
`524f3f2dc9baef696d748db491d49b3055d359d1`. These fixtures exercise string-valued ACL, roles, exact domains, effects, and
keyMatch against the actual Go enforcer and OCaml CLI. They are a declared subset, not a claim of full Casbin compatibility.

`basic_model.conf`, `basic_policy.csv`, `rbac_model.conf`, and `rbac_policy.csv`
were copied byte-for-byte from that checkout's `examples/` directory. `LICENSE`
and `NOTICE` were copied byte-for-byte from its root and apply to those upstream
fixtures. Domain and priority copies are listed in their milestone sections
below; all remaining `.conf` and `.csv` files and `manifest.json` were created
for this port's semantic boundary checks.

The manifest records the pinned revision and an explicit expected OCaml result
for every case: JSON `true`, `false`, or `"error"`. Errors require exit 2, nonempty
stderr, and empty stdout. Successful verdicts require exit 0, empty stderr, and
exactly the Boolean plus a newline on stdout. `oracle_expected` appears only for
explicitly unsupported OCaml models; the observed Go result is still checked,
and the OCaml implementation must reject them. There are no optional oracle
checks and no failure-to-skip conversion.

The runner validates the pinned clean upstream checkout and local Go module
replacement before checking both binaries. Run `python3 scripts/verify_oracle.py`
after building, or use `./scripts/verify.sh` for the complete workflow. Overrides
`--oracle`, `--ocaml`, and `--manifest` are available for controlled local runs;
both binaries are always checked.

Observed reference behaviors captured by the corpus:

- ACL and RBAC match string values exactly, including case, Unicode, empty
  values, quoted commas, and doubled CSV quotes. Any request field count is
  supported when it matches the model; wrong counts are errors.
- Default role depth permits ten edges and denies eleven. A subject has its own
  role even without a self edge. The pinned loader rejects directed role cycles
  and explicit self edges before enforcement.
- Duplicate policy/group rules are skipped. More subtly, upstream indexes rows
  by comma-joining fields, so distinct quoted rows with the same joined key
  collide: the first row wins. Separate p and g fixtures preserve this behavior.
- The file adapter reads physical lines and trims the whole line. Its CSV reader
  trims leading unquoted field spaces but preserves trailing interior spaces
  and quoted spaces. A quoted field spanning physical lines is an error.
- With no policy rules, Go evaluates one synthetic row with empty policy fields;
  constant/request-only matchers can allow, and all-empty ACL fields can match.
- Boolean precedence is `!`, then `&&`, then `||`; parentheses override it.
  Backslashes in matcher literals remain literal characters in this pinned
  source. Date-like strings in requests and policy fields remain ordinary
  strings and match field-to-field normally.
- Casbin preprocessing can rewrite field-like text inside quoted literals;
  govaluate also infers date/time literal types. OCaml conservatively rejects
  these forms under its documented literal restrictions. Opposite quote
  characters inside a literal cause an upstream parse error. Unsupported
  functions and subjectPriority effects remain explicit OCaml rejection
  cases even when Go allows.

The manifest currently contains 684 cases: 635 parity cases and 49 explicit
unsupported-model rejections. Literal preprocessing boundaries also include
terminal `r.`/`p.`, numeric assertion prefixes such as `r2.`, and brackets in a
matcher containing `in`. An unreachable role cycle still causes a load error.

The cases contain both allowed and denied results. Boundary errors are checked
through the same public command contract as successful requests.

## Milestone 2: policy effects

The `effects-*.conf` and `effects-*.csv` fixtures were authored for this port;
they are not copies of upstream files. Every new manifest expectation was
observed by invoking the pinned Go oracle independently. Matrix verdicts were
also checked against the semantics of `effector/default_effector.go` and the
policy/synthetic branches of `enforcer.go`.

The three supported effects are:

| Model effect | Authorization condition |
| --- | --- |
| `some(where (p.eft == allow))` | At least one matched Allow |
| `!some(where (p.eft == deny))` | No matched Deny |
| `some(where (p.eft == allow)) && !some(where (p.eft == deny))` | At least one matched Allow and no matched Deny |

Fixtures place `eft` first, in the middle, and last. Exact lowercase `allow` and
`deny` are the only recognized effect values; unknown, mixed-case, empty, and
space-padded values are Indeterminate. Missing `eft` defaults to Allow. A field
named `act` containing `deny` remains a normal action, not an effect.

The matrix includes conflicting rows in either order, duplicate rows,
unmatched denies, no matches, field-based matchers that reference `eft`, and
transitive RBAC with conflicting role permissions. Allow override authorizes a
matching Allow despite other matching Deny rows. Deny override authorizes even
with no matching Allow and with only Indeterminate rows. Allow-and-deny requires
an actual matching Allow.

Empty-policy and policy-independent matchers use the pinned Go enforcer's
synthetic row: a true matcher yields Allow, a false matcher Indeterminate,
regardless of the explicit `eft` definition or actual nonempty policy effects.
The synthetic policy values are empty strings; `p.eft == ''` therefore matches
and produces Allow. Consequently deny override returns true even for a false
constant matcher, a failed request-only matcher, or an empty-policy matcher
checking `p.eft == 'deny'`. These counterintuitive results are intentional
reference parity.

`unsupported-effect.conf` retains its historical filename but is now tested as
the supported deny-override effect, with no oracle exception.
`effects-unsupported-priority.conf` retains its historical filename but now
uses the supported normal priority effect; its four cases require parity.
`effects-unsupported-subject-priority.conf` remains an explicit rejection
fixture. Its Go verdicts are checked rather than skipped.

## Milestone 4: basic keyMatch

The `keymatch-*.conf` and `keymatch-*.csv` fixtures were authored for this port.
The 116 new expectations were independently observed with the pinned Go oracle;
byte-prefix matrix results were also checked against the first-star semantics
in upstream `util/builtin_operators.go`, lines 171–193.

Without a star, `keyMatch` compares complete strings. With a star, it checks only
the byte prefix preceding the first star, accepting zero or more following
bytes. All suffix text and additional stars are ignored. The matrix covers
exact mismatch/case, too-short prefixes, required slashes, empty keys/patterns,
ignored suffixes, multiple stars, Unicode normalization/variation differences,
and control/whitespace/backslash field values. It also confirms there is no
path normalization or percent decoding. Date-, colon-, bracket-, and hash-shaped
values remain supported when supplied as request/policy fields.

Additional fixtures cover literals under the existing literal restrictions,
parenthesized string operands, policy references in either operand, Boolean
composition, transitive roles, explicit effects, empty-policy synthetic rows,
and request-only matchers. In particular, policy references inside either
`keyMatch` argument must participate in policy-row evaluation. Synthetic and
request-only results retain the previously documented effect behavior.

Invalid zero/one/three argument calls, Boolean/numeric arguments, and a nested
Boolean result used as a string are checked as errors. OCaml compiles and
validates every branch, so unreachable invalid arity/type calls are explicit
rejection cases even when Go returns a short-circuited Boolean. `keyMatch2`
remains unsupported, including in an unreachable branch; both its actual Go
result and OCaml rejection are checked. These strict compile-time boundaries
are represented by separate `oracle_expected` values, never by skipped calls.

`unsupported-function.conf` retains its historical filename but now contains a
supported basic `keyMatch` model tested as ordinary parity. No oracle exception
remains for it.

## Milestone 5: exact-domain RBAC

The new domain fixtures add 78 independently observed pinned-Go cases.
`domain-example.conf`, `domain-example.csv`, `domain-example2.csv`, and
`domain-upstream-hierarchy.csv` are byte-identical copies of upstream examples
`rbac_with_domains_model.conf`, `rbac_with_domains_policy.csv`,
`rbac_with_domains_policy2.csv`, and
`rbac_with_hierarchy_with_domains_policy.csv` respectively. The preserved
upstream LICENSE and NOTICE apply to these copied fixtures. Other `domain-*`
models and policies were authored for this port.

Three-field `g` relationships are isolated by exact domain bytes. Cases cover
upstream examples, transitivity, ten-edge depth, absent-domain self membership,
cross-domain paths and opposing edges, empty/Unicode/comma/space/tab domains,
renamed and reordered fields, literal domain operands, and policy dependencies
present only in the third operand. Effects, object keyMatch, and empty-policy
synthetic rows compose with domain membership.

The strict boundaries are checked explicitly against observed Go results:

- OCaml rejects initial same-domain cycles and explicit self edges. Pinned Go
  skips its default initial detector for DomainManager, which lacks Range.
- A declared three-field role model requires three string operands in every
  matcher branch. Go can query its default empty domain with a two-argument g,
  ignore a fourth operand, or short-circuit a Boolean third operand. A
  three-argument g called against a two-field role declaration also receives a
  strict OCaml compile error even though raw Go ignores that domain.
- A short domain CSV grouping row errors on both sides; an oversized row is
  truncated by Go while OCaml rejects it.
- A matcher shape that activates upstream automatic domain keyMatch
  registration is explicitly rejected by exact-domain OCaml. Object keyMatch
  remains supported when it does not activate that implicit domain matcher.

No divergent initial domain management case is silently skipped: initialization
cycle/self-edge differences are covered in this CLI corpus using explicit
`oracle_expected` values. Management traces start from valid snapshots.


## Milestone 7: priority effects and numeric ordering

173 new expectations were independently observed with the pinned Go oracle,
and the four former normal-priority rejection cases were converted to parity.
`priority-upstream-implicit.conf`, `priority-upstream-implicit.csv`,
`priority-upstream-explicit.conf`, `priority-upstream-explicit.csv`, and
`priority-upstream-indeterminate.csv` were copied byte-for-byte from upstream
`examples/priority_model.conf`, `priority_policy.csv`,
`priority_model_explicit.conf`, `priority_policy_explicit.csv`, and
`priority_indeterminate_policy.csv`, respectively. The preserved LICENSE and
NOTICE apply; all other priority models and policies were authored for this port.

`priority(p.eft) || deny` selects the first matched determinate Allow or Deny.
Unknown, mixed-case, and empty effects are skipped. Missing eft defaults to
Allow; no determinate match denies. Without a priority field, input row order
wins. An exact `priority` field at any position gives stable ascending signed
64-bit order, including equal numeric ties with distinct raw spellings.
The matrix covers first/middle/last positions across all four effects,
negative and explicit-plus priorities, leading/signed zero, signed64 limits,
conflicting rules, unmatched earlier denies, synthetic rows, role examples,
and exact-domain/keyMatch composition.

Fifteen malformed numeric priorities are explicit stricter load boundaries:
empty/whitespace, padded values, hexadecimal, underscores, fractional and
scientific notation, bare signs, overflow, and non-ASCII digits. Pinned Go
accepts each single invalid-priority Allow row; OCaml rejects the retained row.
A duplicate-key pair also verifies validation follows comma-key deduplication:
a valid first row suppresses an invalid key-colliding row, while the inverse
order rejects the retained invalid row. None of these Go observations is skipped.
