#!/usr/bin/env bash
# Re-vendor the object SDK from a cbcl-bus checkout (SPEC-086 ADR-004).
#
#   scripts/vendor-objects.sh ../cbcl-bus
#
# Copies the pinned files byte-for-byte into src/objects/js/vendor/, rewrites
# src/objects/js/VENDOR.json with the cbcl-bus commit, its cbcl-rs.sha and
# every file's SHA-256, and reminds you to move Cargo.toml's cbcl-wasm `rev`
# to the same cbcl-rs.sha. `cargo test --lib objects::` then holds both.
set -euo pipefail
bus="${1:?usage: $0 <path-to-cbcl-bus>}"
here="$(cd "$(dirname "$0")/.." && pwd)"
web="$bus/apps/cbcl_chat/priv/web"
dest="$here/src/objects/js/vendor"
files=(controller.js object-sdk.js emit.js projection.js store.js dialects.js resource-policy.js object-address.js)
for f in "${files[@]}"; do cp "$web/hypermedia/$f" "$dest/$f"; done
cp "$web/cbcl-read.js" "$dest/cbcl-read.js"
commit="$(git -C "$bus" rev-parse HEAD)"
sha="$(tr -d '[:space:]' < "$bus/cbcl-rs.sha")"
{
  echo '{'
  echo '  "source": "cbcl-bus apps/cbcl_chat/priv/web (hypermedia/ plus cbcl-read.js)",'
  echo "  \"cbcl_bus_commit\": \"$commit\","
  echo "  \"cbcl_rs_sha\": \"$sha\","
  echo '  "files": {'
  first=1
  for f in $(ls "$dest" | sort); do
    digest="$(shasum -a 256 "$dest/$f" | cut -d' ' -f1)"
    [ $first -eq 1 ] || echo ','
    first=0
    printf '    "%s": "%s"' "$f" "$digest"
  done
  echo
  echo '  }'
  echo '}'
} > "$here/src/objects/js/VENDOR.json"
echo "vendored from cbcl-bus $commit (cbcl-rs $sha)"
if ! grep -q "rev = \"$sha\"" "$here/Cargo.toml"; then
  echo "NOTE: set Cargo.toml's cbcl-wasm rev to $sha (it must equal cbcl-bus/cbcl-rs.sha)" >&2
fi
