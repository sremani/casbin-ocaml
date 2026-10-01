#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$project_dir/upstream/casbin"
revision=524f3f2dc9baef696d748db491d49b3055d359d1

if [ ! -d "$source_dir/.git" ]; then
  if [ -e "$source_dir" ]; then
    echo "Existing $source_dir is not the expected Git checkout" >&2
    exit 2
  fi
  mkdir -p "$project_dir/upstream"
  git clone --no-checkout https://github.com/apache/casbin.git "$source_dir"
  git -C "$source_dir" checkout --detach "$revision"
fi

actual=$(git -C "$source_dir" rev-parse HEAD)
if [ "$actual" != "$revision" ]; then
  echo "Upstream revision mismatch: expected $revision, got $actual" >&2
  exit 2
fi
if [ -n "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]; then
  echo "Upstream has local changes; refusing to certify a modified oracle" >&2
  exit 2
fi
echo "Pinned Go Casbin: $revision"
