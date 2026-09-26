// Author requests are data; only the trusted host grants resource permissions.
export function viewResources(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !['images', 'styles'].includes(key))) throw new Error('Invalid image/style resource request');
  const result = {};
  for (const kind of ['images', 'styles']) {
    const list = Object.hasOwn(value, kind) ? value[kind] : [];
    if (!Array.isArray(list) || list.length > 8 || new Set(list).size !== list.length) throw new Error('Resource list must contain at most 8 unique URLs');
    result[kind] = Object.freeze(list.map(raw => {
      if (typeof raw !== 'string' || raw.length > 2048 || /[\s"'<>;,*]/.test(raw)) throw new Error('Invalid resource URL');
      let url; try { url = new URL(raw); } catch { throw new Error('Invalid resource URL'); }
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
          || url.pathname.endsWith('/') || url.href !== raw) throw new Error('Resources require canonical HTTPS file URLs without credentials, queries or fragments');
      return raw;
    }));
  }
  return Object.freeze(result);
}

export function resourceCSP(requested, approved = {}) {
  const wanted = viewResources(requested), grants = viewResources(approved);
  for (const kind of ['images','styles']) if (grants[kind].some(url => !wanted[kind].includes(url))) throw new Error('Resource grant was not requested');
  return "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    + (grants.styles.length ? ' ' + grants.styles.join(' ') : '')
    + '; img-src data:' + (grants.images.length ? ' ' + grants.images.join(' ') : '')
    + "; connect-src 'none'; frame-src 'none'; object-src 'none'; worker-src 'none'; form-action 'none'; base-uri 'none'";
}
