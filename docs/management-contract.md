# M3 management contract — CB-201

The OCaml enforcer is an immutable validated snapshot. Add/remove functions return `(new_snapshot, changed)`; callers adopt the returned snapshot. A no-op returns the original snapshot and false. Errors return no candidate snapshot, so the original remains valid.

Support one `p` and optional two-argument `g`: get, has, add and remove policies and grouping links; direct roles for a user and direct users for a role. No persistence, adapters, filtered/batch/update operations, arbitrary role managers, domains, or priority ordering in this wave.

Policy rules must have the declared field count, including `eft` if present. Grouping operations require a role definition. Policy/grouping duplicate identities follow upstream's comma-joined keys, including collisions across distinct quoted tuples. Removal retains the order of remaining rows. Policy additions append within the supported models; models with a `priority` policy field are outside the management parity contract.

Duplicate grouping keys return the original snapshot and false before candidate graph validation, even if the caller's colliding tuple would form a self edge or cycle. No edge is inserted in that case. Every newly stored candidate grouping graph is validated before adoption. Directed cycles and self edges fail, preserving the prior snapshot. This is an intentional stricter boundary than raw upstream in-memory grouping mutations, which can accept cycles until explicit consistency checking/reload. Wrong-arity policy mutations likewise fail immediately; upstream may accept such a row and fail during later enforcement. Valid supported mutation sequences must match Go changed flags, policy/grouping rows, role queries and decisions.

Role query results are sorted lexicographically for reproducibility. Queries return direct links, not transitive role closures. Self membership in enforcement does not create a direct role row.

Another explicit boundary is grouping-key collision removal. Raw Go removes the stored policy row by its joined key, then removes the caller's tuple from its incremental role manager. If those tuples differ, the original role edge can remain after its row is gone. OCaml rebuilds from the remaining rows and removes the original edge. The operation corpus records separate expected traces for this upstream stale-graph case.

## Differential driver contract

Both probe programs take `MODEL POLICY` and read operation lines from stdin. Each line is an operation name followed by tab-separated hexadecimal UTF-8/byte string arguments. No arguments means just the operation name; an empty string is an empty hex field after a tab.

Operations: `enforce`, `get_policy`, `has_policy`, `add_policy`, `remove_policy`, `get_grouping_policy`, `has_grouping_policy`, `add_grouping_policy`, `remove_grouping_policy`, `get_roles_for_user`, `get_users_for_role`.

Each operation emits one line: `true`/`false` for decisions and changed/has flags; `rows\t` followed by semicolon-separated rows with comma-separated hex fields for policy/grouping queries; `values\t` followed by comma-separated sorted hex values for role queries; or `error` for an operation error. A failed operation must not terminate the trace. Invalid initial model/policy terminates with exit 2 and stderr. The probes are verification tools; application callers use the typed library result for diagnostics.

The Go probe calls actual upstream APIs, with autosave disabled. The OCaml probe adopts a returned snapshot only on success. The manifest specifies observed Go and expected OCaml traces; stricter rejected operations are explicitly identified and checked on both sides, never skipped.

Acceptance: baseline corpus remains green, management sequence corpus passes, input snapshots and errors preserve state in OCaml, grouping changes alter later enforcement correctly, packaging still builds, review passes, and PitBoss records M3 in a local commit.
