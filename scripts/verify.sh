#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
./scripts/check_toolchain.sh
./scripts/prepare_upstream.sh
dune build @all
dune runtest
mkdir -p .cache/go-build .cache/go-mod
(cd oracle && GOCACHE="$project_dir/.cache/go-build" GOMODCACHE="$project_dir/.cache/go-mod" go build -mod=readonly -o casbin-oracle .)
(cd oracle && GOCACHE="$project_dir/.cache/go-build" GOMODCACHE="$project_dir/.cache/go-mod" go build -mod=readonly -o casbin-management-oracle ./management)
(cd oracle && GOCACHE="$project_dir/.cache/go-build" GOMODCACHE="$project_dir/.cache/go-mod" go build -mod=readonly -o casbin-abac-oracle ./abac)
python3 scripts/verify_oracle.py
python3 scripts/verify_management.py
python3 scripts/verify_abac.py
