#!/bin/sh
set -eu

for compiler in ocamlc ocamlopt; do
  if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "Missing $compiler: activate the project's OCaml 5.5 toolchain." >&2
    exit 2
  fi
  version=$("$compiler" -version)
  case "$version" in
    5.5.*) ;;
    *)
      echo "Unsupported $compiler version $version: this project requires OCaml 5.5.x. Activate that toolchain in PATH." >&2
      exit 2
      ;;
  esac
done

echo "OCaml toolchain: $version"
