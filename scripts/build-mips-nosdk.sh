#!/usr/bin/env bash
#
# Cross-compile a STATIC mipsel-unknown-linux-musl binary on this machine
# WITHOUT an OpenWrt SDK. Rust's build-std compiles std + our code for mipsel
# and rust-lld links it; the only thing Rust does not ship for this Tier-3
# target is the musl C runtime (a few .o files + libc.a), which we lift out of
# a prebuilt musl cross toolchain -- we use its FILES, never run its gcc.
#
# One-time prerequisites:
#   rustup toolchain install nightly
#   rustup component add rust-src --toolchain nightly
#
# Produces: target/mipsel-unknown-linux-musl/release/pad-gateway
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET=mipsel-unknown-linux-musl
CACHE="${MIPS_MUSL_CACHE:-$HOME/.cache/mipsel-musl}"
LINKDIR="$CACHE/lib"
TC_NAME=mipsel-linux-muslsf-cross
TC_URL="https://more.musl.cc/11/x86_64-linux-musl/$TC_NAME.tgz"

# 1. Fetch the musl runtime files once (crt objects + libc.a; libgcc stands in
#    for -lunwind since we build panic=abort and never actually unwind).
if [ ! -f "$LINKDIR/libc.a" ]; then
  echo ">> fetching musl runtime files into $CACHE"
  mkdir -p "$CACHE"
  tgz="$CACHE/$TC_NAME.tgz"
  [ -f "$tgz" ] || curl -fL --retry 3 -o "$tgz" "$TC_URL"
  tar xzf "$tgz" -C "$CACHE"
  src="$CACHE/$TC_NAME"
  gcc="$src/lib/gcc/mipsel-linux-muslsf/11.2.1"
  mkdir -p "$LINKDIR"
  cp -f "$src/mipsel-linux-muslsf/lib/"{crt1,crti,crtn}.o "$LINKDIR/"
  cp -f "$src/mipsel-linux-muslsf/lib/libc.a"             "$LINKDIR/"
  cp -f "$gcc/"{crtbegin,crtend}.o                        "$LINKDIR/"
  cp -f "$gcc/libgcc.a"                                   "$LINKDIR/libunwind.a"
fi

# 2. Locate the nightly toolchain (rustc/cargo may not be on PATH here) and let
#    the standalone rust-lld find libLLVM via DYLD.
TC="${RUST_NIGHTLY_SYSROOT:-$(ls -d "$HOME"/.rustup/toolchains/nightly-* 2>/dev/null | head -1)}"
if [ -z "$TC" ] || [ ! -x "$TC/bin/cargo" ]; then
  echo "!! nightly toolchain not found; run: rustup toolchain install nightly && rustup component add rust-src --toolchain nightly" >&2
  exit 1
fi
export PATH="$TC/bin:$PATH"
export DYLD_FALLBACK_LIBRARY_PATH="$TC/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"

# 3. Build.
#    - target-cpu=mips32r2 + soft-float: mt7628 has no FPU.
#    - crt-static + our -L: static link against the lifted musl files.
#    - linker=rust-lld: Rust's own linker, no external ld/gcc.
export RUSTFLAGS="-C target-cpu=mips32r2 -C target-feature=+soft-float,+crt-static -C linker=rust-lld -C linker-flavor=ld.lld -L $LINKDIR"

"$TC/bin/cargo" build -Z build-std=std,panic_abort \
  --target "$TARGET" --release \
  --no-default-features --features linux-packet

BIN="target/$TARGET/release/pad-gateway"
echo
file "$BIN"
ls -la "$BIN"

# Size gate for a flash-constrained router (8 MiB).
size=$(stat -f%z "$BIN" 2>/dev/null || stat -c%s "$BIN")
if [ "$size" -gt $((8 * 1024 * 1024)) ]; then
  echo "!! binary exceeds 8 MiB ($size bytes)" >&2
  exit 1
fi
