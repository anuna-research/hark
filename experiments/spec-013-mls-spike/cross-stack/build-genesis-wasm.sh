#!/usr/bin/env bash
# Build BOTH wasm artifacts the R5-03 genesis probe drives:
#   wasm-node/         — the REAL shipped cbcl-mls-wasm (default capabilities;
#                        its KeyPackage must FAIL CLOSED against a genesis group)
#   genesis-wasm-node/ — the spike-local probe build advertising the capability
#                        (must join and read the genesis). Same openmls 0.8.1 +
#                        wasm-bindgen 0.2.114, actual wasm32 target.
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
wasm-pack build --target nodejs --out-dir "$here/genesis-wasm-node" "$here/genesis-wasm"
echo "built wasm-node/ (real artifact) + genesis-wasm-node/ (capability probe)."
echo "Now: node $here/genesis_probe.mjs"
