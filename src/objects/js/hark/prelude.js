globalThis.TextEncoder = class { encode(s) { const out = []; for (const ch of String(s)) { let c = ch.codePointAt(0);
  if (c < 0x80) out.push(c); else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
  else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); } return new Uint8Array(out); } };
globalThis.TextDecoder = class { decode(b) { return decodeURIComponent(Array.from(b, x => '%' + x.toString(16).padStart(2, '0')).join('')); } };
globalThis.console = { log: (...a) => __hark.log('log', a.map(String).join(' ')), error: (...a) => __hark.log('error', a.map(String).join(' ')), warn: (...a) => __hark.log('warn', a.map(String).join(' ')) };
