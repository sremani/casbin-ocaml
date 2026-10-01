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
python3 scripts/verify_oracle.py
