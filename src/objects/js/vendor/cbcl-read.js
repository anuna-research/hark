// cbcl-read.js — the ONE s-expression reader shared by the renderer (app.js)
// and the MLS REQ-018 sender check (mls.js). Having a single parser is
// load-bearing for SPEC-013 REQ-018: the value the security check compares MUST
// be the same value the UI attributes authorship from. Two divergent parsers
// (one for the check, one for display) are a forgery seam — a member could craft
// a frame the check reads one way and the display another. Do not fork this.
//
// This is the display-layer reader, not the authoritative wire recogniser (that
// is cbcl-parser / cbcl-erl on the hub, tracked under DR-1/D-3). Its job here is
// internal consistency between check and render, which it guarantees by being
// the only reader both call.

export function parseSexpr(s) {
  let i = 0;
  function skip() { while (i < s.length && /\s/.test(s[i])) i++; }
  // Decode a quoted string, honouring the escapes the CANONICAL form actually
  // carries. This reader used to treat every `\X` as "drop the backslash, take X
  // literally", which is right for `\\` and `\"` and wrong for `\n`: a newline
  // came back as the letter n.
  //
  // The path is not obvious, which is why it survived. app.js sends a RAW newline
  // (cbclStr escapes only backslash and quote), and the hub's renderer escapes
  // only backslash and quote too — but doSendCBCL canonicalises through
  // parse_message() before signing, and THAT form escapes the newline. So the
  // bytes on the wire are `\n` while both hand-written escapers look innocent.
  // Verified by tapping the socket: an LF typed into the composer leaves as
  // 0x5C 0x6E in both directions.
  //
  // Only n/t/r are decoded. Anything else keeps the previous behaviour exactly,
  // so this is a strict superset — and the file's warning holds: the renderer and
  // the SPEC-013 REQ-018 sender check still read through this one function, so
  // they cannot disagree about what a frame says.
  function readString() {
    let v = '';
    while (i < s.length && s[i] !== '"') {
      if (s[i] !== '\\') { v += s[i++]; continue; }
      i++;
      if (i >= s.length) break;                 // a trailing backslash escapes nothing
      const c = s[i++];
      v += c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c;
    }
    i++;                                        // consume the closing quote
    return v;
  }
  function read() {
    skip();
    if (s[i] === '(') { i++; const l = []; while (true) { skip(); if (s[i] === ')') { i++; break; } l.push(read()); } return l; }
    if (s[i] === '"') { i++; return { str: readString() }; }
    let a = ''; while (i < s.length && !/[\s()]/.test(s[i])) a += s[i++]; return a; // atom/keyword/symbol
  }
  try { return read(); } catch (_) { return null; }
}

// extract keyword args from a parsed list into a map (":k v" pairs)
export function kwargs(list) {
  const m = {};
  if (!Array.isArray(list)) return m;
  for (let j = 0; j < list.length; j++) {
    const t = list[j];
    if (typeof t === 'string' && t.startsWith(':')) { m[t.slice(1)] = list[j + 1]; j++; }
  }
  return m;
}

export const asText = (v) => (v && v.str !== undefined) ? v.str : (typeof v === 'string' ? v : JSON.stringify(v));
