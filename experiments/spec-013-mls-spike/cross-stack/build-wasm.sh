#!/usr/bin/env bash
# Build the REAL cbcl-mls-wasm artifact for nodejs into ./wasm-node, so the
# cross-stack harness drives the actual `.wasm` the web client ships (not a second
# copy of native code). Pinned: openmls 0.8.1, wasm-bindgen 0.2.114 — same as the
# native spike, so any byte interop is genuine.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
crate="${CBCL_MLS_WASM:-$here/../../../../cbcl-chat/crates/cbcl-mls-wasm}"

if [[ ! -f "$crate/Cargo.toml" ]]; then
  echo "cbcl-mls-wasm crate not found at: $crate" >&2
  echo "set CBCL_MLS_WASM to its path and re-run." >&2
  exit 2
fi

command -v wasm-pack >/dev/null || { echo "wasm-pack not installed" >&2; exit 2; }

wasm-pack build --target nodejs --out-dir "$here/wasm-node" "$crate"
echo "wasm-node/ built. Now: node $here/cross_stack.mjs"
