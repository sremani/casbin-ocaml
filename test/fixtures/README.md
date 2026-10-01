# Differential fixture corpus

Reference: [Apache Casbin](https://github.com/apache/casbin), pinned commit
`524f3f2dc9baef696d748db491d49b3055d359d1`. These fixtures exercise the first
string-valued ACL/basic RBAC milestone against the actual Go enforcer and OCaml
CLI. They are a declared subset, not a claim of full Casbin compatibility.

`basic_model.conf`, `basic_policy.csv`, `rbac_model.conf`, and `rbac_policy.csv`
were copied byte-for-byte from that checkout's `examples/` directory. `LICENSE`
and `NOTICE` were copied byte-for-byte from its root and apply to those upstream
fixtures. Other `.conf` and `.csv` files and `manifest.json` were created for this
port's semantic boundary checks.

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
  function and priority-effect models are explicit OCaml rejection cases even when Go allows.

The manifest currently contains 317 cases: 293 parity cases and 24 explicit
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
`effects-unsupported-priority.conf` and
`effects-unsupported-subject-priority.conf` remain explicit OCaml rejection
fixtures. Their Go verdicts are checked rather than skipped.
