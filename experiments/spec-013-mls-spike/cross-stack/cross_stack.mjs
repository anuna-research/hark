// Node orchestrator for the SPEC-013 §10 cross-stack confirmation (NFR-001).
//
// Drives the REAL `cbcl-mls-wasm` artifact (built for nodejs in ./wasm-node) and
// the NATIVE OpenMLS peer (../src/bin/native_peer.rs) over a JSON-line stdio
// protocol, exchanging MLS wire bytes as hex. This is the genuine cross-stack
// test the spike README deferred: not native↔native, but native ⇄ the compiled
// `.wasm` the web client ships.
//
// native (hark stack) = group creator + committer "native-alice"
// wasm  (web stack)   = added member "wasm-bob"
// Asserts BOTH directions: native→wasm (Welcome + app message) and wasm→native.
//
// Run:  node cross-stack/cross_stack.mjs   (after build-wasm.sh)

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// The wasm-bindgen nodejs binding is CommonJS.
const wasmPath = join(__dirname, 'wasm-node', 'cbcl_mls_wasm.js');
let wasm;
try {
  wasm = require(wasmPath);
} catch (e) {
  console.error(`could not load wasm binding at ${wasmPath}\n` +
    `run ./cross-stack/build-wasm.sh first.\n${e}`);
  process.exit(2);
}

const toHex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

// --- spawn the native peer (cargo run; -q so stdout is clean JSON) -------------
const manifest = join(__dirname, '..', 'Cargo.toml');
const native = spawn('cargo',
  ['run', '-q', '--manifest-path', manifest, '--bin', 'native_peer'],
  { stdio: ['pipe', 'pipe', 'inherit'] });

const rl = createInterface({ input: native.stdout });
const pending = [];
rl.on('line', (line) => {
  if (!line.trim()) return;
  const waiter = pending.shift();
  if (waiter) waiter(JSON.parse(line));
});
native.on('exit', (code) => { if (code) { console.error(`native exited ${code}`); process.exit(1); } });

const rpc = (obj) => new Promise((resolve) => {
  pending.push(resolve);
  native.stdin.write(JSON.stringify(obj) + '\n');
});

function assert(cond, msg) { if (!cond) { console.error(`FAIL: ${msg}`); native.stdin.write('{"cmd":"bye"}\n'); process.exit(1); } }

// --- the cross-stack exchange --------------------------------------------------
async function main() {
  // 1. wasm member builds its KeyPackage (real .wasm).
  const provider = new wasm.Provider();
  const identity = new wasm.Identity(provider, 'wasm-bob');
  const kp = identity.key_package(provider);          // Uint8Array
  console.log(`[xstack] wasm-bob KeyPackage: ${kp.length} bytes`);

  // 2. native validates + adds it, returns a Welcome + a native→wasm app message.
  const added = await rpc({ cmd: 'add', kp: toHex(kp) });
  assert(!added.error, `native add failed: ${added.error}`);
  assert(added.members === 2, `native group should have 2 members, got ${added.members}`);
  console.log(`[xstack] native added wasm-bob; group members = ${added.members}`);

  // 3. wasm joins the native-produced Welcome (native→wasm wire bytes).
  const group = wasm.Group.join(provider, fromHex(added.welcome));
  console.log(`[xstack] wasm joined native Welcome; wasm sees ${group.member_count()} members`);
  assert(group.member_count() === 2, 'wasm should see 2 members after joining');

  // 4. wasm decrypts the native app message  → native→wasm CONFIRMED.
  const outN = group.process(provider, fromHex(added.ct));
  assert(outN, 'wasm could not decrypt the native application message');
  const textN = new TextDecoder().decode(outN);
  console.log(`[xstack] native→wasm decrypted: "${textN}"`);
  assert(textN === 'hi from native (native->wasm)', `unexpected native→wasm plaintext: ${textN}`);

  // 5. wasm encrypts an app message; native decrypts it → wasm→native CONFIRMED.
  const ct2 = group.encrypt(provider, identity, new TextEncoder().encode('hi from wasm (wasm->native)'));
  const dec = await rpc({ cmd: 'decrypt', ct: toHex(ct2) });
  assert(!dec.error, `native decrypt failed: ${dec.error}`);
  console.log(`[xstack] wasm→native decrypted: "${dec.plaintext}" (sender leaf ${dec.sender_leaf})`);
  assert(dec.plaintext === 'hi from wasm (wasm->native)', `unexpected wasm→native plaintext: ${dec.plaintext}`);

  // 'bye' gets no reply (native breaks its loop) — fire-and-forget, then let node
  // exit naturally so stdout flushes (process.exit() would truncate it).
  native.stdin.write('{"cmd":"bye"}\n');
  native.stdin.end();
  rl.close();
  console.log('\n[xstack] PASS — native OpenMLS 0.8.1 ⇄ compiled cbcl-mls-wasm interoperate both directions at the pinned ciphersuite. NFR-001 confirmed cross-stack.');
  process.exitCode = 0;
}

main().catch((e) => { console.error(e); process.exit(1); });
