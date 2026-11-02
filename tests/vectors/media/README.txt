cbcl-bus SPEC-101 interoperability fixtures

Source checkout: cbcl-bus at 114dbb4efbf2698ae36d77bf4e87d53de3d22802.
Browser codec files updated unchanged from cbcl-bus at
97f9fd52dd4c09b16e54d5d31e3f8cd874edca5a (opaque attachment contract).
Copied from apps/cbcl_chat/priv/web:
  media-ref.mjs SHA-256 37662d265dd9ec87a7aa2695d5b605bce4e1364f76c03a18ab0295b7af422d4a
  media-uri.mjs SHA-256 67804ebcdd92caf44498b7bbb5ed4555207663ca86a0102268fe9aa0e1d062d6
browser.json is test/web/fixtures/media-ref-vector.json, an independent Node
AES-GCM/HMAC oracle also used by the browser codec suite.
file-contract.json was compiled through that checkout's cbcl/object/index.js
using the definition from object-starters/file.mjs (presentation excluded).

storage.mjs is a test-only local HTTPS server. The committed localhost private
key is deliberately public test material; the CA signing key was discarded.
Certificates are valid October 2026 through October 2036 and trusted only by
the test client. No production TLS trust bypass is present.

Media tests require Node (WebCrypto/HTTPS fixtures) only. Metadata inspection runs in process.

sample.* are original cbcl-bus test assets decoded from FIXTURES in
apps/cbcl_chat/test/web/media-metadata.test.mjs at the same source pin.
