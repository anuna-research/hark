// Node orchestrator for the R5-03 cross-stack genesis-extension probe (SPEC-013
// REQ-016 durable delivery + the leaf-capabilities obligation).
//
// native (hark stack) = creator of a group carrying the genesis bytes in a pinned
// Unknown(0xF013) GroupContext extension, creator leaf advertising the type.
//
// Leg 1 — FAIL-CLOSED against the REAL artifact: the shipped cbcl-mls-wasm
//   (./wasm-node) publishes a default-capability KeyPackage; native's add MUST be
//   rejected (InsufficientCapabilities). This is the cross-repo obligation
//   observed against the artifact the web client actually ships.
// Leg 2 — POSITIVE against the capability probe build (./genesis-wasm-node, same
//   openmls 0.8.1 on wasm32): its KeyPackage advertises Unknown(0xF013); the add
//   MUST succeed, the wasm joiner MUST read the genesis bytes from the Welcome's
//   GroupContext byte-identically, and the group must then carry traffic
//   wasm→native.
//
// Run:  node cross-stack/genesis_probe.mjs   (after build-genesis-wasm.sh)

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function load(name, dir) {
  const p = join(__dirname, dir, name);
  try {
    return require(p);
  } catch (e) {
    console.error(`could not load wasm binding at ${p}\nrun ./cross-stack/build-genesis-wasm.sh first.\n${e}`);
    process.exit(2);
  }
}
const realWasm = load('cbcl_mls_wasm.js', 'wasm-node');
const probeWasm = load('genesis_wasm_probe.js', 'genesis-wasm-node');

const toHex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

const manifest = join(__dirname, '..', 'Cargo.toml');
const native = spawn('cargo',
  ['run', '-q', '--manifest-path', manifest, '--bin', 'genesis_peer'],
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

async function main() {
  const expected = await rpc({ cmd: 'genesis' });
  console.log(`[R5-03 xstack] native genesis-bearing group up; genesis = ${fromHex(expected.genesis).length} bytes`);

  // ---- Leg 1: REAL shipped cbcl-mls-wasm, default capabilities → fail closed.
  {
    const provider = new realWasm.Provider();
    const identity = new realWasm.Identity(provider, 'wasm-bob');
    const kp = identity.key_package(provider);
    const r = await rpc({ cmd: 'add', kp: toHex(kp) });
    assert(r.error, 'REAL cbcl-mls-wasm default-capability KeyPackage was ACCEPTED into a genesis-bearing group — the capabilities obligation is NOT enforced; REQ-016/REQ-017 must be re-shaped');
    assert(/InsufficientCapabilities|UnsupportedExtensions/.test(r.error),
      `rejected, but not with the expected capability error: ${r.error}`);
    console.log(`[R5-03 xstack] LEG 1 (fail-closed, REAL artifact): native REJECTED the shipped wasm KeyPackage — ${r.error}`);
  }

  // ---- Leg 2: capability probe build → join + read genesis + carry traffic.
  {
    const provider = new probeWasm.Provider();
    const identity = new probeWasm.Identity(provider, 'wasm-bob');
    const kp = identity.key_package_with_genesis_capability(provider);
    const r = await rpc({ cmd: 'add', kp: toHex(kp) });
    assert(!r.error, `capability-advertising wasm KeyPackage rejected: ${r.error}`);
    assert(r.members === 2, `native group should have 2 members, got ${r.members}`);
    console.log('[R5-03 xstack] LEG 2: native ACCEPTED the capability-advertising wasm KeyPackage');

    const group = probeWasm.Group.join(provider, fromHex(r.welcome));
    assert(group.member_count() === 2, 'wasm should see 2 members after joining');
    const genesis = group.genesis();
    assert(genesis, 'wasm joiner could not read the genesis GroupContext extension');
    assert(toHex(genesis) === expected.genesis,
      `genesis bytes differ across stacks: wasm=${toHex(genesis)} native=${expected.genesis}`);
    console.log(`[R5-03 xstack] LEG 2: wasm joined the Welcome and read the genesis byte-identically (${genesis.length} bytes)`);

    const ct = group.encrypt(provider, identity, new TextEncoder().encode('genesis group carries traffic'));
    const dec = await rpc({ cmd: 'decrypt', ct: toHex(ct) });
    assert(!dec.error, `native decrypt failed: ${dec.error}`);
    assert(dec.plaintext === 'genesis group carries traffic', `unexpected plaintext: ${dec.plaintext}`);
    console.log(`[R5-03 xstack] LEG 2: wasm→native app message decrypted in the genesis-bearing group (sender leaf ${dec.sender_leaf})`);
  }

  native.stdin.write('{"cmd":"bye"}\n');
  native.stdin.end();
  rl.close();
  console.log('\n[R5-03 xstack] PASS — (1) the REAL shipped cbcl-mls-wasm KeyPackage fails closed against a genesis-bearing group (capabilities obligation is load-bearing and enforced by openmls 0.8.1); (2) with the capability advertised, native ⇄ wasm32 round-trip create→add→welcome→read the genesis GroupContext extension byte-identically and the group carries traffic.');
  process.exitCode = 0;
}

main().catch((e) => { console.error(e); process.exit(1); });
