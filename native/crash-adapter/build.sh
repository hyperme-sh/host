#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source=${1:?Usage: build.sh VISOR_SOURCE OUTPUT}
output=${2:?Usage: build.sh VISOR_SOURCE OUTPUT}
expected=$(python3 - "$repo/native/crash-adapter/Cargo.toml" <<'PY'
import sys,tomllib
with open(sys.argv[1],'rb') as stream:
    print(tomllib.load(stream)['dependencies']['hypermesh-crash-retention']['rev'])
PY
)
[[ $(git -C "$source" rev-parse HEAD) == "$expected" ]] || { echo 'Native authority source mismatch' >&2; exit 1; }
[[ ! -e "$output" ]] || { echo 'Output already exists' >&2; exit 1; }
bash "$source/native/crash/build-sdk.sh" "$output"
output=$(cd "$output" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo test --locked --manifest-path "$repo/native/crash-adapter/Cargo.toml" --target-dir "$work/rust" --lib
cargo build --locked --release --manifest-path "$repo/native/crash-adapter/Cargo.toml" --target-dir "$work/rust"
cmake -S "$repo/native/crash-adapter" -B "$work/native" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$output" \
  -DCMAKE_INSTALL_PREFIX="$output" \
  -DHOST_RUST_ARCHIVE="$work/rust/release/libhypermesh_host_crash_adapter.a"
cmake --build "$work/native" --parallel 2
"$work/native/host-crash-options-contract"
cmake --install "$work/native"
mkdir -p "$output/service"
cp "$source/native/crash/service/hypermesh-host-crash-retention.service" "$output/service/"
cp "$source/native/crash/service/sh.hyperme.host.crash-retention.plist" "$output/service/"
git -C "$repo" rev-parse HEAD > "$output/host-source-revision"
# Source revisions identify this downloadable artifact, not a running service pin.
