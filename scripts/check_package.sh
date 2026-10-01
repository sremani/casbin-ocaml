#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
./scripts/check_toolchain.sh
dune build @install
package_check_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/casbin-package-check.XXXXXX")
trap 'rm -rf "$package_check_dir"' EXIT HUP INT TERM
prefix="$package_check_dir/prefix"
if ! dune install --prefix "$prefix" --sections lib,bin > "$package_check_dir/install.log" 2>&1; then
  cat "$package_check_dir/install.log" >&2
  exit 1
fi
mkdir "$package_check_dir/consumer"
cp examples/installed_consumer.ml "$package_check_dir/consumer/consumer.ml"
cat > "$package_check_dir/consumer/dune-project" <<'PROJECT'
(lang dune 3.1)
PROJECT
cat > "$package_check_dir/consumer/dune" <<'DUNE'
(executable (name consumer) (libraries casbin_ocaml))
DUNE
OCAMLPATH="$prefix/lib${OCAMLPATH:+:$OCAMLPATH}" dune exec --root "$package_check_dir/consumer" ./consumer.exe
model="$project_dir/test/fixtures/rbac_model.conf"
policy="$project_dir/test/fixtures/rbac_policy.csv"
test "$("$prefix/bin/casbin-ocaml" "$model" "$policy" alice data2 read)" = true
test "$("$prefix/bin/casbin-ocaml" "$model" "$policy" alice missing read)" = false
set +e
"$prefix/bin/casbin-ocaml" "$model" "$policy" alice > "$package_check_dir/stdout" 2> "$package_check_dir/stderr"
error_status=$?
set -e
test "$error_status" = 2
test ! -s "$package_check_dir/stdout"
test -s "$package_check_dir/stderr"
echo "Installed CLI: allow, deny and error exit/output checks passed"
