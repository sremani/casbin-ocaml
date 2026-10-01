# Pinned Go Casbin oracle

The oracle uses the unmodified local `../upstream/casbin` checkout at commit
`524f3f2dc9baef696d748db491d49b3055d359d1` through `go.mod`'s local replacement.
Its Go module checksum file locks the public transitive dependencies. The wrapper
uses `casbin.NewEnforcer(modelPath, policyPath)` and `Enforce` with string-valued
request arguments, preserving the standard file adapter's behavior.

From the project root, prepare the checkout with `./scripts/prepare_upstream.sh`,
then build with:

```sh
mkdir -p .cache/go-build .cache/go-mod
project_dir=$(pwd)
(cd oracle && GOCACHE="$project_dir/.cache/go-build" GOMODCACHE="$project_dir/.cache/go-mod" go build -mod=readonly -o casbin-oracle .)
```

The first build downloads public Go modules. `./scripts/verify.sh` builds both
implementations and runs the differential corpus.

```sh
oracle/casbin-oracle test/fixtures/basic_model.conf test/fixtures/basic_policy.csv alice data1 read
# true
python3 scripts/verify_oracle.py
```

Invocation is `casbin-oracle MODEL POLICY [REQUEST...]`; the request may have any
number of strings, including zero. Successful enforcement writes exactly `true`
or `false` plus a newline to stdout. Input, model, policy, and enforcement errors
write a diagnostic to stderr and exit 2 with empty stdout. Panics are converted
to the same error contract. The wrapper does not suppress source-model errors or
substitute its own authorization result.
