cbcl-bus SPEC-101 interoperability fixtures

Source checkout: cbcl-bus at 114dbb4efbf2698ae36d77bf4e87d53de3d22802.
Browser codec files copied unchanged from apps/cbcl_chat/priv/web:
  media-ref.mjs SHA-256 0b882801bd47875787f50652b683ce7d4353077e0935123ab38e4e517f1dd290
  media-uri.mjs SHA-256 67804ebcdd92caf44498b7bbb5ed4555207663ca86a0102268fe9aa0e1d062d6
browser.json is test/web/fixtures/media-ref-vector.json, an independent Node
AES-GCM/HMAC oracle also used by the browser codec suite.
file-contract.json was compiled through that checkout's cbcl/object/index.js
using the definition from object-starters/file.mjs (presentation excluded).

storage.mjs is a test-only local HTTPS server. The committed localhost private
key is deliberately public test material; the CA signing key was discarded.
Certificates are valid October 2026 through October 2036 and trusted only by
the test client. No production TLS trust bypass is present.

Media tests require Node (WebCrypto/HTTPS fixtures) and ffprobe (metadata).

sample.* are original cbcl-bus test assets decoded from FIXTURES in
apps/cbcl_chat/test/web/media-metadata.test.mjs at the same source pin.
