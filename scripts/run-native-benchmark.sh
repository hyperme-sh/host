#!/bin/sh
# Run the native collector with an independently reviewed llama.cpp release.
set -eu
umask 077

if [ "$#" -ne 7 ]; then
    echo "Usage: $0 COLLECTOR RUNTIME_ARCHIVE ARCHIVE_SHA256 MODEL MODEL_SHA256 STATE_DIR ARTIFACT_DIR" >&2
    exit 2
fi

collector=$1 archive=$2 archive_sha=$3 model=$4 model_sha=$5 state=$6 artifacts=$7
for path in "$collector" "$archive" "$model" "$state" "$artifacts"; do
    case "$path" in
        /*) ;;
        *) echo "Use absolute paths for benchmark inputs and output" >&2; exit 2 ;;
    esac
done

case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) backend=metal; device=MTL0 ;;
    Linux/x86_64) backend=vulkan; device=Vulkan0 ;;
    *) echo "Supported benchmark hosts are Apple silicon and Linux x86_64" >&2; exit 2 ;;
esac

for pin in "$archive_sha" "$model_sha"; do
    if ! printf '%s\n' "$pin" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "Use lowercase SHA-256 pins" >&2
        exit 2
    fi
done

if [ ! -d "$state" ] || [ ! -r "$state" ] || [ ! -x "$state" ]; then
    echo "The agent state directory must be readable by the benchmark operator" >&2
    exit 1
fi

if [ -e "$state/lease.json" ] || [ -L "$state/lease.json" ]; then
    echo "Benchmark refused while a lease checkpoint exists" >&2
    exit 1
fi

sha256() {
    shasum -a 256 < "$1" | cut -d ' ' -f 1
}
mkdir -p "$artifacts"
runtime=$(mktemp -d "$artifacts/runtime.XXXXXXXX")
cp "$archive" "$runtime/release.tar.gz"
if [ "$(sha256 "$runtime/release.tar.gz")" != "$archive_sha" ]; then
    echo "Runtime archive digest does not match the reviewed pin" >&2
    exit 1
fi

# Keep the full extraction intact because llama-bench loads adjacent dylibs/so files.
tar -xzf "$runtime/release.tar.gz" -C "$runtime"
rm "$runtime/release.tar.gz"
bench=$(find "$runtime" -type f -name llama-bench -print)
if [ ! -f "$bench" ] || [ ! -x "$bench" ]; then
    echo "Expected exactly one executable llama-bench in the release archive" >&2
    exit 1
fi

"$collector" measure-certification \
    --model-file "$model" --model-sha256 "$model_sha" \
    --runtime-file "$bench" --runtime-sha256 "$(sha256 "$bench")" \
    --backend "$backend" --device "$device" --context-tokens 16384 \
    --generated-tokens 32 --samples 3 --state-dir "$state" --artifact-dir "$artifacts"
