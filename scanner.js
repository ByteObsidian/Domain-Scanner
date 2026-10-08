// Domain scanning pipeline: WHOIS (RDAP) -> DNS -> HTTP -> redirects -> title -> IP -> hosting.
// Runs inside an extension page, so it has host permissions (no CORS limits) and DOMParser.

export const STEPS = ['whois', 'dns', 'http', 'redirect', 'title', 'ssl', 'ip', 'hosting'];

const RDAP_FALLBACK = 'https://rdap.org/';
// TLDs with working RDAP that are missing from the IANA bootstrap file.
const RDAP_OVERRIDES = {
  io: 'https://rdap.identitydigital.services/rdap/',
  ac: 'https://rdap.identitydigital.services/rdap/',
  sh: 'https://rdap.identitydigital.services/rdap/',
};
// ARIN redirects to the correct RIR (RIPE, APNIC, LACNIC, AFRINIC) for any IP.
const IP_RDAP_BASES = ['https://rdap.arin.net/registry/ip/', 'https://rdap.org/ip/'];
const RDAP_ACCEPT = 'application/rdap+json, application/json';
const HTTP_TIMEOUT = 12000;
const BODY_LIMIT = 256 * 1024;
const HEAD_EXTRA = 16 * 1024; // keep reading this much past </head> for early redirect scripts

// ---------- helpers ----------

async function fetchJSON(url, { timeout = 10000, accept = 'application/json' } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { Accept: accept },
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return await res.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Timed out');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export function normalizeDomain(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  try {
    const host = new URL(s).hostname.replace(/\.$/, '').toLowerCase();
    if (!host.includes('.') || /^\[|^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

const stripWww = (h) => h.replace(/^www\./, '');
const uniq = (arr) => [...new Set(arr.filter(Boolean))];
const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isIPv6 = (s) => /^[0-9a-f:]+$/i.test(s) && s.includes(':');

// ---------- Cache (memory + chrome.storage.local) ----------

const HOUR = 3600 * 1000;
export const CACHE_TTL = { bootstrap: 24 * HOUR, whois: 24 * HOUR, hosting: 24 * HOUR, ssl: 6 * HOUR };
const CACHE_PREFIX = 'cache:';
const memCache = new Map();
const storage = typeof chrome !== 'undefined' && chrome.storage?.local ? chrome.storage.local : null;

async function cached(key, ttl, fn, fresh = false) {
  const k = CACHE_PREFIX + key;
  if (!fresh) {
    let hit = memCache.get(k);
    if (!hit && storage) { try { hit = (await storage.get(k))[k]; } catch { /* ignore */ } }
    if (hit && Date.now() - hit.t < ttl) return hit.v;
  }
  const v = await fn();
  const entry = { t: Date.now(), v };
  memCache.set(k, entry);
  storage?.set({ [k]: entry }).catch(() => {});
  return v;
}

// Drop expired entries so storage doesn't grow without bound.
export async function pruneCache() {
  if (!storage) return;
  try {
    const all = await storage.get(null);
    const maxTtl = Math.max(...Object.values(CACHE_TTL));
    const stale = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX) && Date.now() - (all[k]?.t || 0) > maxTtl);
    if (stale.length) await storage.remove(stale);
  } catch { /* ignore */ }
}

// ---------- RDAP / vCard parsing ----------

function flatten(v) {
  return Array.isArray(v) ? v.flatMap(flatten) : [v];
}

function parseVcard(entity) {
  const out = { emails: [], tels: [] };
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) return out;
  for (const [name, params, , value] of props) {
    switch (name) {
      case 'fn': out.fn = value; break;
      case 'org': out.org = flatten(value).filter(Boolean).join(' '); break;
      case 'email': if (/@/.test(value)) out.emails.push(String(value)); break;
      case 'tel': out.tels.push(String(value).replace(/^tel:/i, '')); break;
      case 'url': out.url = value; break;
      case 'adr':
        out.address = params?.label || flatten(value).filter(Boolean).join(', ');
        if (params?.cc) out.country = params.cc;
        break;
    }
  }
  return out;
}

function findEntities(entities, role, acc = []) {
  for (const e of entities || []) {
    if (e.roles?.includes(role)) acc.push(e);
    findEntities(e.entities, role, acc);
  }
  return acc;
}

function abuseContact(entities) {
  for (const e of findEntities(entities, 'abuse')) {
    const v = parseVcard(e);
    if (v.emails.length || v.tels.length) return { email: v.emails[0] || null, phone: v.tels[0] || null };
  }
  return { email: null, phone: null };
}

// IANA bootstrap files (dns / ipv4 / ipv6). Order: fresh cached copy -> copy bundled in the
// extension (instant). A network refresh runs in the background so the cache stays current.
const bootstrapPromises = {};
function getBootstrap(kind = 'dns') {
  if (!bootstrapPromises[kind]) {
    bootstrapPromises[kind] = (async () => {
      const key = CACHE_PREFIX + `rdap-bootstrap-${kind}`;
      let hit = memCache.get(key);
      if (!hit && storage) { try { hit = (await storage.get(key))[key]; } catch { /* ignore */ } }
      const fresh = hit && Date.now() - hit.t < CACHE_TTL.bootstrap;
      if (!fresh) {
        cached(`rdap-bootstrap-${kind}`, 0, () => fetchJSON(`https://data.iana.org/rdap/${kind}.json`), true)
          .catch(() => {});
      }
      if (hit) return hit.v;
      try {
        return await fetchJSON(new URL(`./data/rdap-${kind}.json`, import.meta.url).href);
      } catch {
        return fetchJSON(`https://data.iana.org/rdap/${kind}.json`);
      }
    })().catch((e) => {
      delete bootstrapPromises[kind];
      throw e;
    });
  }
  return bootstrapPromises[kind];
}

async function rdapBaseFor(domain) {
  try {
    const bs = await getBootstrap();
    const labels = domain.split('.');
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');
      for (const [tlds, urls] of bs.services) {
        if (tlds.includes(suffix)) {
          const base = urls.find((u) => u.startsWith('https')) || urls[0];
          return base.endsWith('/') ? base : base + '/';
        }
      }
    }
  } catch { /* fall through */ }
  return RDAP_OVERRIDES[domain.split('.').pop()] || RDAP_FALLBACK;
}

function parseDomainRdap(data) {
  const registrarEntity = findEntities(data.entities, 'registrar')[0];
  const rv = parseVcard(registrarEntity);
  let abuse = abuseContact(registrarEntity?.entities);
  if (!abuse.email) abuse = abuseContact(data.entities);

  const events = {};
  for (const ev of data.events || []) events[ev.eventAction] = ev.eventDate;

  const registrantEntity = findEntities(data.entities, 'registrant')[0];
  const reg = parseVcard(registrantEntity);

  const related = (data.links || []).find(
    (l) => l.rel === 'related' && /rdap/i.test(l.type || '') && l.href
  );

  return {
    registrar: {
      name: rv.fn || rv.org || registrarEntity?.handle || null,
      ianaId: registrarEntity?.publicIds?.find((p) => /iana/i.test(p.type))?.identifier || null,
      url: rv.url || null,
      abuseEmail: abuse.email,
      abusePhone: abuse.phone,
      whoisServer: data.port43 || null,
    },
    registrant: {
      org: reg.org || reg.fn || null,
      country: reg.country || null,
    },
    created: events.registration || null,
    updated: events['last changed'] || null,
    expires: events.expiration || null,
    status: data.status || [],
    nameservers: (data.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
    dnssec: data.secureDNS ? !!data.secureDNS.delegationSigned : null,
    relatedUrl: related?.href || null,
  };
}

// Common two-level public suffixes, so we can guess the registrable domain in one try.
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.br', 'net.br', 'org.br', 'com.cn', 'net.cn', 'org.cn', 'com.hk', 'com.tw', 'com.sg', 'com.my',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.tr', 'com.ua', 'com.pk', 'com.ph', 'com.vn', 'co.id',
  'co.za', 'com.ng', 'com.eg', 'com.sa', 'co.il', 'co.th',
  'com.uy', 'org.uy', 'net.uy', 'edu.uy', 'gub.uy', 'mil.uy',
]);

function registrableGuess(host) {
  const l = host.split('.');
  if (l.length <= 2) return host;
  return MULTI_SUFFIXES.has(l.slice(-2).join('.')) ? l.slice(-3).join('.') : l.slice(-2).join('.');
}

export function whoisLookup(domain, fresh = false) {
  const guess = registrableGuess(domain);
  return cached(`whois:${guess}`, CACHE_TTL.whois, () => whoisUncached(domain, guess), fresh);
}

async function rdapWhois(domain, guess) {
  // Best guess at the registrable domain first, then the other levels (RDAP only knows registrable domains).
  const labels = domain.split('.');
  const others = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.')).filter((c) => c !== guess && c.includes('.'));
  const candidates = [guess, ...others.reverse()];
  let lastErr = null;
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    const base = await rdapBaseFor(candidate);
    const url = `${base}domain/${candidate}`;
    let data;
    try {
      data = await fetchJSON(url, { accept: RDAP_ACCEPT });
    } catch (e) {
      // Registries answer subdomain queries with 404 or 400/422; retry with the parent.
      const clientError = e.status >= 400 && e.status < 500 && e.status !== 429;
      if (!(clientError && lastErr?.status === 404)) lastErr = e;
      if (clientError && i < candidates.length - 1) continue;
      break;
    }
    const parsed = parseDomainRdap(data);
    parsed.queried = candidate;
    parsed.source = url;

    // Registry (thin) responses can lack registrar details; only then ask the registrar's RDAP.
    const missing = !parsed.registrar.abuseEmail || !parsed.registrar.name || !parsed.created;
    if (missing && parsed.relatedUrl && parsed.relatedUrl !== url) {
      try {
        const extra = parseDomainRdap(await fetchJSON(parsed.relatedUrl, { accept: RDAP_ACCEPT, timeout: 6000 }));
        for (const k of Object.keys(parsed.registrar)) parsed.registrar[k] ??= extra.registrar[k];
        parsed.registrant.org ??= extra.registrant.org;
        parsed.registrant.country ??= extra.registrant.country;
        parsed.created ??= extra.created;
        parsed.expires ??= extra.expires;
      } catch { /* registrar RDAP is optional */ }
    }
    return parsed;
  }
  const err = new Error(
    lastErr?.status === 404
      ? 'Domain not found in RDAP (unregistered, or TLD has no RDAP service)'
      : `RDAP lookup failed: ${lastErr?.message || 'unknown error'}`
  );
  err.status = lastErr?.status;
  throw err;
}

// ---------- WHOIS fallback for TLDs without RDAP ----------

async function hasRdapService(domain) {
  const tld = domain.split('.').pop();
  if (RDAP_OVERRIDES[tld]) return true;
  try {
    const bs = await getBootstrap();
    return bs.services.some(([tlds]) => tlds.includes(tld));
  } catch {
    return true;
  }
}

async function postJSON(url, body, { timeout = 10000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status });
    return await res.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Timed out');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

const emptyWhois = () => ({
  registrar: { name: null, ianaId: null, url: null, abuseEmail: null, abusePhone: null, whoisServer: null },
  registrant: { org: null, country: null, name: null, email: null, phone: null },
  created: null, updated: null, expires: null, status: [], nameservers: [], dnssec: null, relatedUrl: null,
});

// .uy: registered directly with the registry (ANTEL / NIC Uruguay); there is no separate registrar.
// Uses the registry's public web lookup, which asks for a CAPTCHA only after many queries.
async function uyWhois(domain) {
  const url = 'https://dns2-edge.sva.antel.com.uy/dominio/consulta/whois';
  const d = await postJSON(url, { dominio: { nombre: domain }, captchaResponse: '', wcv: false });
  if (d.codigo === 'ERROR_DOMINIO_NO_EXISTE') throw new Error('Domain is not registered (NIC Uruguay)');
  if (d.codigo === 'CAPTCHA_INVALIDO') throw new Error('NIC Uruguay lookup limit reached; try again later or use nic.com.uy/consulta-whois');
  if (!d.respuestaOK) throw new Error(`NIC Uruguay lookup failed: ${d.mensaje || d.codigo || 'unknown error'}`);
  const w = emptyWhois();
  const t = d.titular || {};
  w.registrar.name = 'Dominios uy (ANTEL)';
  w.registrar.note = 'Registered directly with the .uy registry; there is no separate registrar.';
  w.registrar.url = 'https://nic.com.uy/';
  w.registrant = { org: null, country: 'UY', name: t.nombre || null, email: t.email || null, phone: t.telefono || null };
  w.created = d.fechaAlta || null;
  w.status = d.estado ? [d.estado.toLowerCase()] : [];
  w.nameservers = (d.nameServers || []).map((n) => String(n).replace(/\.$/, '').toLowerCase());
  w.source = 'https://nic.com.uy/consulta-whois';
  return w;
}

// Generic fallback: who-dat (free WHOIS-over-HTTP service). Best effort; some registries time out.
async function whoDatWhois(domain) {
  const d = await fetchJSON(`https://who-dat.as93.net/${encodeURIComponent(domain)}`, { timeout: 9000 });
  if (d.error) throw new Error(`WHOIS lookup failed: ${d.error.message || d.error.code}`);
  if (d.isRegistered === false) throw new Error('Domain is not registered');
  const w = emptyWhois();
  const r = d.registrar || {};
  Object.assign(w.registrar, {
    name: r.name || null, ianaId: r.ianaId || null, url: r.url || null,
    abuseEmail: r.abuseEmail || null, abusePhone: r.abusePhone || null, whoisServer: r.whoisServer || null,
  });
  const reg = d.contacts?.registrant || {};
  w.registrant = {
    org: reg.organization || null, country: reg.address?.country || null,
    name: reg.name || null, email: reg.email || null, phone: reg.phone || null,
  };
  w.created = d.dates?.created || null;
  w.updated = d.dates?.updated || null;
  w.expires = d.dates?.expires || null;
  w.status = d.status || [];
  w.nameservers = (d.nameservers || []).map((n) => String(n.name || n).replace(/\.$/, '').toLowerCase());
  w.dnssec = d.dnssec ? !!d.dnssec.signed : null;
  w.source = `https://who-dat.as93.net/${domain}`;
  return w;
}

const WHOIS_FALLBACKS = { uy: uyWhois };

async function whoisUncached(domain, guess) {
  if (await hasRdapService(guess)) return rdapWhois(domain, guess);
  {
    const fallback = WHOIS_FALLBACKS[guess.split('.').pop()] || whoDatWhois;
    try {
      const w = await fallback(guess);
      w.queried = guess;
      w.viaWhois = true;
      return w;
    } catch (e) {
      throw new Error(`No RDAP service for .${guess.split('.').pop()}; ${e.message}`);
    }
  }
}

// ---------- DNS (DNS-over-HTTPS) ----------

const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, TXT: 16 };
const TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPES).map(([k, v]) => [v, k]));

function dohQuery(name, type) {
  const q = `name=${encodeURIComponent(name)}&type=${type}`;
  return Promise.any([
    fetchJSON(`https://dns.google/resolve?${q}`, { timeout: 6000 }),
    fetchJSON(`https://cloudflare-dns.com/dns-query?${q}`, { timeout: 6000, accept: 'application/dns-json' }),
  ]);
}

export async function dnsLookup(domain, onType = () => {}) {
  const records = Object.fromEntries(Object.keys(DNS_TYPES).map((t) => [t, []]));
  let nxdomain = false;
  let failures = 0;

  await Promise.all(
    Object.keys(DNS_TYPES).map(async (type) => {
      try {
        const d = await dohQuery(domain, type);
        if (d.Status === 3) nxdomain = true;
        for (const a of d.Answer || []) {
          const t = TYPE_NAMES[a.type];
          if (t) records[t].push(String(a.data).replace(/^"|"$/g, ''));
        }
        onType(type, (d.Answer || []).filter((a) => a.type === DNS_TYPES[type]).map((a) => a.data));
      } catch {
        failures++;
        onType(type, []);
      }
    })
  );

  if (failures === Object.keys(DNS_TYPES).length) throw new Error('All DNS-over-HTTPS queries failed');
  for (const t of Object.keys(records)) records[t] = uniq(records[t]);
  return { nxdomain, records };
}

// ---------- HTTP + redirect tracking via webRequest ----------

const tracked = new Map(); // startUrl -> { requestId, hops, ip, status }
const byRequestId = new Map();
let listenersReady = false;

function ensureListeners() {
  if (listenersReady || !chrome?.webRequest) return;
  listenersReady = true;
  const filter = { urls: ['<all_urls>'] };
  const ours = (d) => !d.initiator || d.initiator === location.origin;

  chrome.webRequest.onBeforeRequest.addListener((d) => {
    if (!ours(d)) return;
    const t = tracked.get(d.url);
    if (t && !t.requestId) {
      t.requestId = d.requestId;
      byRequestId.set(d.requestId, t);
    }
  }, filter);

  chrome.webRequest.onBeforeRedirect.addListener((d) => {
    const t = byRequestId.get(d.requestId);
    if (t) t.hops.push({ from: d.url, to: d.redirectUrl, status: d.statusCode, ip: d.ip || null });
  }, filter);

  chrome.webRequest.onResponseStarted.addListener((d) => {
    const t = byRequestId.get(d.requestId);
    if (t) { t.ip = d.ip || null; t.status = d.statusCode; }
  }, filter);
}

function startTracking(url) {
  ensureListeners();
  const t = { requestId: null, hops: [], ip: null, status: null };
  tracked.set(url, t);
  return t;
}

function stopTracking(url, t) {
  tracked.delete(url);
  if (t.requestId) byRequestId.delete(t.requestId);
}

async function readText(res, limit) {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let size = 0;
  let headEnd = -1;
  let tail = '';
  const probe = new TextDecoder('latin1');
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
    // Title, meta refresh and most redirect scripts live in <head>; stop shortly after it closes.
    if (headEnd < 0) {
      const text = tail + probe.decode(value, { stream: true });
      const i = text.search(/<\/head\s*>/i);
      if (i >= 0) headEnd = size;
      tail = text.slice(-16);
    } else if (size - headEnd >= HEAD_EXTRA) {
      break;
    }
  }
  reader.cancel().catch(() => {});
  const buf = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) { buf.set(c.subarray(0, size - off), off); off += c.length; if (off >= size) break; }
  const charset = /charset=([^;]+)/i.exec(res.headers.get('content-type') || '')?.[1]?.trim();
  try { return new TextDecoder(charset || 'utf-8').decode(buf); }
  catch { return new TextDecoder('utf-8').decode(buf); }
}

function analyseHtml(html, baseUrl) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const title =
    doc.querySelector('title')?.textContent?.trim().replace(/\s+/g, ' ') ||
    doc.querySelector('meta[property="og:title"]')?.getAttribute('content')?.trim() ||
    null;

  let metaRefresh = null;
  for (const m of doc.querySelectorAll('meta[http-equiv]')) {
    if ((m.getAttribute('http-equiv') || '').toLowerCase() !== 'refresh') continue;
    const target = /url\s*=\s*['"]?([^'"]+)/i.exec(m.getAttribute('content') || '')?.[1];
    if (target) {
      try { metaRefresh = new URL(target.trim(), baseUrl).href; } catch { metaRefresh = target.trim(); }
    }
  }

  let jsRedirect = null;
  const js = /(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]|location\.(?:replace|assign)\(\s*['"]([^'"]+)['"]/i.exec(html);
  if (js) {
    const target = js[1] || js[2];
    try { jsRedirect = new URL(target, baseUrl).href; } catch { jsRedirect = target; }
  }
  return { title, metaRefresh, jsRedirect };
}

export async function httpCheck(domain) {
  const attempts = [];
  for (const scheme of ['https', 'http']) {
    const url = `${scheme}://${domain}/`;
    const t = startTracking(url);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT);
    try {
      const res = await fetch(url, {
        redirect: 'follow',
        credentials: 'omit',
        cache: 'no-store',
        signal: ctrl.signal,
      });
      const contentType = res.headers.get('content-type') || '';
      const body = /html|text|xml/i.test(contentType) || !contentType ? await readText(res, BODY_LIMIT) : '';
      await new Promise((r) => setTimeout(r, 50)); // let webRequest events land

      let redirects = t.hops.map(({ from, to, status }) => ({ from, to, status }));
      if (!redirects.length && res.redirected) redirects = [{ from: url, to: res.url, status: null }];

      const html = body ? analyseHtml(body, res.url) : { title: null, metaRefresh: null, jsRedirect: null };
      const finalHost = new URL(res.url).hostname;

      return {
        requestedUrl: url,
        finalUrl: res.url,
        status: res.status,
        statusText: res.statusText,
        headers: {
          server: res.headers.get('server'),
          contentType,
          poweredBy: res.headers.get('x-powered-by'),
          all: Object.fromEntries(res.headers.entries()),
        },
        redirects,
        redirected: redirects.length > 0,
        crossDomain: stripWww(finalHost) !== stripWww(domain),
        metaRefresh: html.metaRefresh,
        jsRedirect: html.jsRedirect,
        title: html.title,
        connectedIp: t.ip,
        attempts,
      };
    } catch (e) {
      attempts.push(`${scheme.toUpperCase()}: ${e.name === 'AbortError' ? 'timed out' : e.message}`);
    } finally {
      clearTimeout(timer);
      stopTracking(url, t);
    }
  }
  const err = new Error(`Site unreachable (${attempts.join('; ')})`);
  err.attempts = attempts;
  throw err;
}

// ---------- Hosting provider (IP RDAP + ipwho.is) ----------

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) + Number(o)) >>> 0, 0);
}

function ipv6ToBigInt(ip) {
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const fill = tail !== undefined ? 8 - h.length - t.length : 0;
  return [...h, ...Array(fill).fill('0'), ...t].reduce((acc, part) => (acc << 16n) + BigInt(parseInt(part || '0', 16)), 0n);
}

function inCidr(ip, cidr) {
  const [net, bits] = cidr.split('/');
  const len = Number(bits);
  if (isIPv4(ip) && isIPv4(net)) {
    const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
    return ((ipv4ToInt(ip) & mask) >>> 0) === ((ipv4ToInt(net) & mask) >>> 0);
  }
  if (isIPv6(ip) && net.includes(':')) {
    const shift = BigInt(128 - len);
    return (ipv6ToBigInt(ip) >> shift) === (ipv6ToBigInt(net) >> shift);
  }
  return false;
}

async function rirBaseFor(ip) {
  try {
    const bs = await getBootstrap(isIPv4(ip) ? 'ipv4' : 'ipv6');
    for (const [cidrs, urls] of bs.services) {
      if (cidrs.some((c) => inCidr(ip, c))) {
        const base = urls.find((u) => u.startsWith('https')) || urls[0];
        return (base.endsWith('/') ? base : base + '/') + 'ip/';
      }
    }
  } catch { /* fall back to ARIN, which redirects */ }
  return null;
}

// IANA's /8 map is coarse (many blocks were transferred between registries), so ask the mapped
// registry and ARIN (which redirects anywhere) at the same time and take the first answer.
async function ipRdap(ip) {
  const [arin, fallback] = IP_RDAP_BASES;
  const direct = await rirBaseFor(ip);
  const get = (base) => fetchJSON(base + ip, { accept: RDAP_ACCEPT });
  try {
    return await Promise.any(uniq([direct, arin]).map(get));
  } catch {
    return get(fallback);
  }
}

// Cached per /24 (IPv4) or /48 (IPv6): round-robin DNS returns sibling IPs with the same owner.
export async function hostingLookup(ip, fresh = false) {
  const net = isIPv4(ip) ? ip.split('.').slice(0, 3).join('.') : ip.split(':').slice(0, 3).join(':');
  const data = await cached(`hosting:${net}`, CACHE_TTL.hosting, () => hostingUncached(ip), fresh);
  return { ...data, ip };
}

async function hostingUncached(ip) {
  const [rdapRes, geoRes] = await Promise.allSettled([
    ipRdap(ip),
    fetchJSON(`https://ipwho.is/${ip}`),
  ]);
  const rdap = rdapRes.status === 'fulfilled' ? rdapRes.value : null;
  const geo = geoRes.status === 'fulfilled' && geoRes.value?.success !== false ? geoRes.value : null;
  if (!rdap && !geo) throw new Error('IP RDAP and geolocation lookups both failed');

  let org = null, network = null, abuse = { email: null, phone: null }, source = null;
  if (rdap) {
    const owner =
      findEntities(rdap.entities, 'registrant')[0] ||
      findEntities(rdap.entities, 'administrative')[0] ||
      rdap.entities?.[0];
    const ov = parseVcard(owner);
    org = ov.fn || ov.org || null;
    abuse = abuseContact(rdap.entities);
    const cidr = rdap.cidr0_cidrs?.[0];
    network = {
      name: rdap.name || null,
      handle: rdap.handle || null,
      range: cidr
        ? `${cidr.v4prefix || cidr.v6prefix}/${cidr.length}`
        : rdap.startAddress ? `${rdap.startAddress} – ${rdap.endAddress}` : null,
      country: rdap.country || null,
    };
    source = rdap.port43 || (rdap.links || []).find((l) => l.rel === 'self')?.href || null;
  }

  const conn = geo?.connection || {};
  return {
    ip,
    provider: conn.org || conn.isp || org || network?.name || null,
    isp: conn.isp || null,
    asn: conn.asn ? `AS${conn.asn}` : null,
    rdapOrg: org,
    network,
    abuseEmail: abuse.email,
    abusePhone: abuse.phone,
    location: geo ? [geo.city, geo.region, geo.country].filter(Boolean).join(', ') : null,
    source,
  };
}

// ---------- SSL certificates (Certificate Transparency logs) ----------

const CERTSPOTTER = 'https://api.certspotter.com/v1/issuances';
const CERT_PAGES = 3;

function coversHost(name, host) {
  name = name.toLowerCase();
  if (name === host) return true;
  return name.startsWith('*.') && host.endsWith(name.slice(1)) &&
    host.split('.').length === name.split('.').length;
}

function issuerOrg(dn) {
  return /(?:^|,\s*)O=("[^"]+"|[^,]+)/.exec(dn || '')?.[1]?.replace(/"/g, '') ||
    /(?:^|,\s*)CN=([^,]+)/.exec(dn || '')?.[1] || dn || null;
}

async function certsFromCertSpotter(host) {
  const certs = [];
  let after = null;
  let truncated = false;
  for (let page = 0; page < CERT_PAGES; page++) {
    const url = `${CERTSPOTTER}?domain=${encodeURIComponent(host)}&match_wildcards=true&expand=dns_names&expand=issuer` +
      (after ? `&after=${after}` : '');
    const batch = await fetchJSON(url, { timeout: 15000 });
    for (const c of batch) {
      certs.push({
        issuer: c.issuer?.friendly_name || issuerOrg(c.issuer?.name),
        issuerDn: c.issuer?.name || null,
        notBefore: c.not_before,
        notAfter: c.not_after,
        dnsNames: c.dns_names || [],
        revoked: !!c.revoked,
      });
    }
    if (batch.length < 100) break;
    after = batch[batch.length - 1].id;
    if (page === CERT_PAGES - 1) truncated = true;
  }
  return { certs, truncated, source: 'Cert Spotter' };
}

async function certsFromCrtSh(host) {
  const rows = await fetchJSON(
    `https://crt.sh/?q=${encodeURIComponent(host)}&output=json&exclude=expired&deduplicate=Y`,
    { timeout: 10000 }
  );
  const certs = rows
    .map((c) => ({
      issuer: issuerOrg(c.issuer_name),
      issuerDn: c.issuer_name,
      notBefore: c.not_before + 'Z',
      notAfter: c.not_after + 'Z',
      dnsNames: uniq(String(c.name_value || '').split('\n')),
      revoked: false,
    }))
    .filter((c) => c.dnsNames.some((n) => coversHost(n, host)));
  return { certs, truncated: false, source: 'crt.sh' };
}

export function certLookup(host, fresh = false) {
  return cached(`ssl:${host}`, CACHE_TTL.ssl, () => certUncached(host), fresh);
}

// When Cert Spotter's free quota (~100/hour) runs out, skip it for a while instead of asking every scan.
const CERTSPOTTER_BACKOFF = 30 * 60 * 1000;
const BACKOFF_KEY = 'certspotter-blocked-until';

async function certSpotterBlocked() {
  let until = memCache.get(BACKOFF_KEY);
  if (until == null && storage) { try { until = (await storage.get(BACKOFF_KEY))[BACKOFF_KEY]; } catch { /* ignore */ } }
  return Date.now() < (until || 0);
}

function blockCertSpotter() {
  const until = Date.now() + CERTSPOTTER_BACKOFF;
  memCache.set(BACKOFF_KEY, until);
  storage?.set({ [BACKOFF_KEY]: until }).catch(() => {});
}

async function certUncached(host) {
  let res;
  if (await certSpotterBlocked()) {
    res = await certsFromCrtSh(host);
  } else {
    try { res = await certsFromCertSpotter(host); }
    catch (e) {
      if (e.status === 429) blockCertSpotter();
      res = await certsFromCrtSh(host);
    }
  }

  const now = Date.now();
  const active = res.certs.filter((c) => new Date(c.notAfter) > now && new Date(c.notBefore) <= now && !c.revoked);
  const latest = active.sort((a, b) => new Date(b.notBefore) - new Date(a.notBefore))[0];
  return {
    found: !!latest,
    issuer: latest?.issuer || null,
    issuerDn: latest?.issuerDn || null,
    issued: latest?.notBefore || null,
    expires: latest?.notAfter || null,
    dnsNames: (latest?.dnsNames || []).slice(0, 50),
    sanCount: latest?.dnsNames?.length || 0,
    activeCount: active.length,
    activeCountTruncated: res.truncated,
    issuers: uniq(active.map((c) => c.issuer)),
    source: res.source,
    link: `https://crt.sh/?q=${encodeURIComponent(host)}`,
  };
}

// ---------- CDN / reverse-proxy detection ----------

const CDNS = [
  {
    name: 'Cloudflare', asns: ['AS13335', 'AS209242'], org: /cloudflare/i,
    headers: (h) => h['cf-ray'] || /cloudflare/i.test(h.server || ''), cname: /\.cdn\.cloudflare\.net$/,
    abuseEmail: 'abuse@cloudflare.com', abuseForm: 'https://abuse.cloudflare.com/',
  },
  {
    name: 'Akamai', asns: ['AS20940', 'AS16625', 'AS21342', 'AS35994'], org: /akamai/i,
    headers: (h) => /akamai/i.test(h.server || '') || h['x-akamai-transformed'] || h['akamai-grn'],
    cname: /\.(akamaiedge|edgekey|edgesuite|akamai|akamaized|akamaihd)\.net$/,
    abuseEmail: 'abuse@akamai.com',
  },
  {
    name: 'Fastly', asns: ['AS54113'], org: /fastly/i,
    headers: (h) => h['x-fastly-request-id'] || /cache-\w+/.test(h['x-served-by'] || ''),
    cname: /\.(fastly|fastlylb)\.net$/,
    abuseEmail: 'abuse@fastly.com',
  },
  {
    name: 'Amazon CloudFront', asns: [], org: /cloudfront/i,
    headers: (h) => h['x-amz-cf-id'] || /cloudfront/i.test(`${h.via || ''} ${h.server || ''}`),
    cname: /\.cloudfront\.net$/,
    abuseEmail: 'abuse@amazonaws.com', abuseForm: 'https://support.aws.amazon.com/#/contacts/report-abuse',
  },
  {
    name: 'Azure Front Door / CDN', asns: [], org: null,
    headers: (h) => h['x-azure-ref'] || h['x-msedge-ref'], cname: /\.(azureedge|azurefd)\.net$/,
    abuseForm: 'https://msrc.microsoft.com/report/abuse',
  },
  {
    name: 'Imperva (Incapsula)', asns: ['AS19551'], org: /incapsula|imperva/i,
    headers: (h) => h['x-iinfo'] || /incapsula|imperva/i.test(h['x-cdn'] || ''), cname: /\.incapdns\.net$/,
  },
  {
    name: 'Sucuri', asns: ['AS30148'], org: /sucuri/i,
    headers: (h) => h['x-sucuri-id'] || /sucuri/i.test(h.server || ''), cname: /\.sucuri\.net$/,
  },
  {
    name: 'DDoS-Guard', asns: ['AS57724', 'AS262254'], org: /ddos-guard/i,
    headers: (h) => /ddos-guard/i.test(h.server || ''), cname: /ddos-guard/,
    abuseEmail: 'abuse@ddos-guard.net',
  },
  {
    name: 'BunnyCDN', asns: ['AS200325'], org: /bunny/i,
    headers: (h) => /bunnycdn/i.test(h.server || ''), cname: /\.b-cdn\.net$/,
  },
  {
    name: 'StackPath', asns: ['AS33438'], org: /stackpath|highwinds/i,
    headers: (h) => h['x-hw'], cname: /\.stackpathdns\.com$/,
  },
];

export function detectCdn(result) {
  const headers = result.http?.ok ? result.http.data.headers.all || {} : {};
  const cnames = result.dns?.ok ? result.dns.data.records.CNAME.map((c) => c.replace(/\.$/, '').toLowerCase()) : [];
  const h = result.hosting?.ok ? result.hosting.data : null;
  const orgText = [h?.provider, h?.isp, h?.rdapOrg, h?.network?.name].filter(Boolean).join(' ');

  for (const cdn of CDNS) {
    const evidence = [];
    if (cdn.headers(headers)) evidence.push('HTTP response headers');
    const cn = cnames.find((c) => cdn.cname.test(c));
    if (cn) evidence.push(`CNAME ${cn}`);
    if (h?.asn && cdn.asns.includes(h.asn)) evidence.push(`IP in ${h.asn}`);
    else if (cdn.org && cdn.org.test(orgText)) evidence.push('IP owner');
    if (evidence.length) {
      return { name: cdn.name, evidence, abuseEmail: cdn.abuseEmail || null, abuseForm: cdn.abuseForm || null };
    }
  }
  return null;
}

// ---------- Orchestration ----------

async function settle(promise) {
  try { return { ok: true, data: await promise }; }
  catch (e) { return { ok: false, error: e.message || String(e) }; }
}

// opts: { onStep(step, state), onUpdate(partialResult), fresh }  (fresh = bypass cache)
export async function scanDomain(domain, opts = {}) {
  const { onStep = () => {}, onUpdate = () => {}, fresh = false } = typeof opts === 'function' ? { onStep: opts } : opts;
  const result = { domain, scannedAt: new Date().toISOString() };
  const update = () => { result.cdn = detectCdn(result); onUpdate(result); };
  STEPS.forEach((s) => onStep(s, 'running'));

  const whoisP = settle(whoisLookup(domain, fresh)).then((r) => {
    result.whois = r;
    onStep('whois', r.ok ? 'ok' : 'fail');
    update();
  });

  const httpP = settle(httpCheck(domain)).then((r) => {
    result.http = r;
    onStep('http', r.ok ? 'ok' : 'fail');
    onStep('redirect', r.ok ? (r.data.redirected || r.data.metaRefresh || r.data.jsRedirect ? 'warn' : 'ok') : 'skip');
    onStep('title', r.ok && r.data.title ? 'ok' : r.ok ? 'warn' : 'skip');
    update();
  });

  // Hosting starts as soon as the A (or AAAA) answer arrives, without waiting for MX/TXT/NS.
  let resolveIp;
  const ipP = new Promise((r) => { resolveIp = r; });
  const got = {};
  const dnsP = settle(dnsLookup(domain, (type, answers) => {
    if (type !== 'A' && type !== 'AAAA') return;
    got[type] = answers;
    const v4 = (got.A || []).filter(isIPv4);
    if (v4.length) resolveIp(v4[0]);
    else if (got.A && got.AAAA) resolveIp(got.AAAA.filter(isIPv6)[0] || null);
  })).then((r) => {
    result.dns = r;
    onStep('dns', r.ok ? (r.data.nxdomain ? 'fail' : 'ok') : 'fail');
    const all = r.ok ? [...r.data.records.A.filter(isIPv4), ...r.data.records.AAAA.filter(isIPv6)] : [];
    result.ip = { primary: all[0] || null, all };
    onStep('ip', all.length ? 'ok' : 'fail');
    resolveIp(all[0] || null);
    update();
  });

  const hostingP = ipP.then(async (ip) => {
    if (!ip) {
      result.hosting = { ok: false, error: 'No IP address resolved' };
      onStep('hosting', 'skip');
      return;
    }
    result.hosting = await settle(hostingLookup(ip, fresh));
    onStep('hosting', result.hosting.ok ? 'ok' : 'fail');
    update();
  });

  const sslP = settle(certLookup(domain, fresh)).then((r) => {
    result.ssl = r;
    onStep('ssl', r.ok ? (r.data.found ? 'ok' : 'warn') : 'fail');
    update();
  });

  await Promise.all([whoisP, httpP, dnsP, hostingP, sslP]);
  result.cdn = detectCdn(result);
  return result;
}
