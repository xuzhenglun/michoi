#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/openwrt-sdk" >&2
    exit 2
fi

sdk=$1
target=mipsel-unknown-linux-musl
linker=$(find "$sdk/staging_dir" -type f -name '*-openwrt-linux-musl-gcc' | head -n 1)
if [ -z "$linker" ]; then
    echo "OpenWrt musl gcc not found below $sdk/staging_dir" >&2
    exit 1
fi

export STAGING_DIR="$sdk/staging_dir"
export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$linker"
export RUSTFLAGS="-C target-cpu=mips32r2 -C target-feature=+soft-float"

# mipsel-unknown-linux-musl is a Rust Tier-3 target, so std must be rebuilt.
cargo +nightly build \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target "$target" \
    --release \
    --no-default-features \
    --features linux-packet

binary="target/$target/release/pad-gateway"
bytes=$(wc -c < "$binary" | tr -d ' ')
limit=$((8 * 1024 * 1024))
if [ "$bytes" -gt "$limit" ]; then
    echo "size gate failed: $bytes bytes exceeds 8 MiB" >&2
    exit 1
fi
echo "$binary: $bytes bytes"

