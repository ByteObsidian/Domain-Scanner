import { scanDomain, normalizeDomain, pruneCache, STEPS } from './scanner.js';

const STEP_LABELS = {
  whois: 'WHOIS', dns: 'DNS', http: 'HTTP', redirect: 'Redirect', title: 'Title', ssl: 'SSL', ip: 'IP', hosting: 'Hosting',
};
const CONCURRENCY = 6;
const MAX_DOMAINS = 100;

const $ = (s) => document.querySelector(s);
const input = $('#domains');
const scanBtn = $('#scan');
const results = $('#results');
const statusEl = $('#status');
const exportCsvBtn = $('#exportCsv');
const exportJsonBtn = $('#exportJson');

let lastResults = [];
const tabUrls = new Map(); // host -> full URL of the tab it came from

if (new URLSearchParams(location.search).has('tab')) document.body.classList.add('full');

// ---------- View mode (normal by default, remembered per browser) ----------

function setView(mode, persist = true) {
  const detailed = mode === 'detailed';
  document.body.classList.toggle('detailed', detailed);
  $('#viewNormal').setAttribute('aria-pressed', String(!detailed));
  $('#viewDetailed').setAttribute('aria-pressed', String(detailed));
  if (persist) chrome.storage.local.set({ viewMode: mode }).catch(() => {});
}
$('#viewNormal').addEventListener('click', () => setView('normal'));
$('#viewDetailed').addEventListener('click', () => setView('detailed'));
chrome.storage.local.get('viewMode').then(({ viewMode }) => setView(viewMode || 'normal', false)).catch(() => {});

// ---------- DOM helpers (all untrusted data goes through textContent) ----------

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

const none = (text = 'Not available') => el('span', { class: 'none', text });

function safeLink(url, text = url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return el('a', { href: u.href, target: '_blank', rel: 'noopener noreferrer', text });
    }
  } catch { /* not a URL */ }
  return el('span', { text });
}

function copyBtn(value, label = 'Copy') {
  const b = el('button', { class: 'mini ghost', title: label, text: label });
  b.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      b.textContent = 'Copied';
      setTimeout(() => (b.textContent = label), 1200);
    } catch { b.textContent = 'Failed'; }
  });
  return b;
}

const mailtoHref = (email, subject, body) =>
  `mailto:${encodeURIComponent(email).replace(/%40/g, '@')}` +
  (subject ? `?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}` : '');

function emailNode(email) {
  if (!email) return none('No abuse email published');
  return el('span', {}, el('a', { href: mailtoHref(email), target: '_blank', text: email }), copyBtn(email));
}

// ---------- Abuse report ----------

function buildReport(r, recipient) {
  const w = r.whois?.ok ? r.whois.data : null;
  const h = r.hosting?.ok ? r.hosting.data : null;
  const x = r.http?.ok ? r.http.data : null;
  const s = r.ssl?.ok && r.ssl.data.found ? r.ssl.data : null;
  const age = domainAge(w?.created);
  const lines = [
    `Hello ${recipient || ''} abuse team,`.replace('  ', ' '),
    '',
    'We are reporting the domain below, which appears to be involved in phishing / malicious activity. ' +
      'Please investigate and take appropriate action.',
    '',
    `Domain: ${r.domain}`,
    r.pageUrl ? `URL: ${r.pageUrl}` : x ? `URL: ${x.finalUrl}` : null,
    x && r.pageUrl && x.finalUrl !== r.pageUrl ? `Final URL: ${x.finalUrl}` : null,
    r.ip?.primary ? `IP address: ${r.ip.primary}` : null,
    w?.registrar.name ? `Registrar: ${w.registrar.name}${w.registrar.ianaId ? ` (IANA ID ${w.registrar.ianaId})` : ''}` : null,
    h?.provider ? `Hosting provider: ${h.provider}${h.asn ? ` (${h.asn})` : ''}` : null,
    r.cdn ? `CDN / proxy: ${r.cdn.name}` : null,
    mxStatus(r)?.exists ? `Mail servers (MX): ${mxStatus(r).hosts.map((h) => h.host).join(', ')}` : null,
    w?.created ? `Domain created: ${fmtDate(w.created)}${age ? ` (${age.text} old)` : ''}` : null,
    s ? `SSL certificate: ${s.issuer}, issued ${fmtDate(s.issued)}` : null,
    x?.title ? `Page title: ${x.title.slice(0, 150)}` : null,
    x?.redirected ? `Redirect chain: ${[...x.redirects.map((hop) => hop.from), x.finalUrl].slice(0, 6).join(' -> ')}` : null,
    '',
    'Evidence: [add screenshots / details here]',
    '',
    `Scanned (UTC): ${r.scannedAt.replace('T', ' ').slice(0, 19)}`,
    '',
    'Regards,',
  ];
  return {
    subject: `Abuse report: phishing / malicious activity on ${r.domain}`,
    body: lines.filter((l) => l !== null).join('\n'),
  };
}

function reportActions(r, recipient, email, form) {
  const { subject, body } = buildReport(r, recipient);
  return el('div', { class: 'report-actions' },
    email ? el('a', { class: 'mini-btn primary', href: mailtoHref(email, subject, body), target: '_blank', text: '✉ Report' }) : null,
    form ? safeLink(form, 'Abuse form ↗') : null,
    copyBtn(`Subject: ${subject}\n\n${body}`, 'Copy report'),
  );
}

function cdnNote(r, h) {
  const c = r.cdn;
  if (!c) return null;
  const separateContact = c.abuseEmail && c.abuseEmail !== h?.abuseEmail;
  return el('div', { class: 'cdn-note' },
    el('div', {}, el('strong', { text: `Behind ${c.name}` }), ' — the real hosting server is hidden. Report to the CDN; they forward to the origin host.'),
    el('div', { class: 'sub', text: `Detected via: ${c.evidence.join(', ')}` }),
    separateContact ? el('div', { class: 'email' }, emailNode(c.abuseEmail)) : null,
    separateContact || c.abuseForm ? reportActions(r, c.name, separateContact ? c.abuseEmail : null, c.abuseForm) : null,
  );
}

// MX status: exists / null MX (RFC 7505, "0 .") / none. Returns null while DNS is pending.
function mxStatus(r) {
  if (!r.dns) return null;
  if (!r.dns.ok) return { exists: null, label: 'Unknown (DNS lookup failed)', cls: 'fail', hosts: [] };
  const hosts = r.dns.data.records.MX
    .map((v) => {
      const [pref, host = ''] = String(v).trim().split(/\s+/);
      return { pref: Number(pref), host: host.replace(/\.$/, '').toLowerCase() };
    })
    .sort((a, b) => a.pref - b.pref);
  if (!hosts.length) return { exists: false, label: 'No MX record', cls: 'warn', hosts };
  if (hosts.every((h) => !h.host)) return { exists: false, label: 'Null MX: domain does not accept email', cls: 'warn', hosts: [] };
  return { exists: true, label: `MX record found (${hosts.length})`, cls: 'ok', hosts: hosts.filter((h) => h.host) };
}

function mxLine(r) {
  const mx = mxStatus(r);
  if (!mx) return pending();
  const shown = mx.hosts.slice(0, 2).map((h) => h.host).join(', ');
  const more = mx.hosts.length > 2 ? ` +${mx.hosts.length - 2} more` : '';
  return el('span', { class: `age ${mx.cls}` }, el('strong', { text: mx.label }), shown ? ` · ${shown}${more}` : null);
}

const fmtDate = (s) => {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d) ? s : d.toISOString().slice(0, 10);
};

const NEW_DOMAIN_DAYS = 90;
const VERY_NEW_DOMAIN_DAYS = 30;

function domainAge(created) {
  const t = new Date(created).getTime();
  if (!created || isNaN(t)) return null;
  const days = Math.max(0, Math.floor((Date.now() - t) / 864e5));
  const years = Math.floor(days / 365.25);
  const months = Math.floor(days / 30.44);
  const text = years >= 1 ? `${years} year${years > 1 ? 's' : ''}`
    : months >= 1 ? `${months} month${months > 1 ? 's' : ''}`
    : `${days} day${days !== 1 ? 's' : ''}`;
  if (days < VERY_NEW_DOMAIN_DAYS) return { days, text, label: 'Very new domain', cls: 'fail', isNew: true };
  if (days < NEW_DOMAIN_DAYS) return { days, text, label: 'New domain', cls: 'warn', isNew: true };
  return { days, text, label: 'Established domain', cls: 'ok', isNew: false };
}

function ageNode(created) {
  const age = domainAge(created);
  if (!age) return none('Unknown (no creation date)');
  return el('span', { class: `age ${age.cls}` }, el('strong', { text: age.label }), ` · ${age.text} old`);
}

function kv(rows) {
  const dl = el('dl');
  for (const [label, value, cls] of rows) {
    const node = value == null || value === '' || (Array.isArray(value) && !value.length)
      ? none()
      : value instanceof Node ? value : Array.isArray(value) ? value.join(', ') : String(value);
    dl.append(el('dt', { text: label }), el('dd', { class: cls }, node));
  }
  return dl;
}

const section = (title, cls, ...content) => el('div', { class: `section ${cls || ''}` }, el('h3', { text: title }), ...content);
const errorLine = (msg) => el('div', { class: 'error', text: msg });
const pending = () => el('div', { class: 'none loading', text: 'Looking up…' });
// Error if the lookup finished and failed, spinner text if it hasn't finished yet.
const failOrPending = (part) => (part ? errorLine(part.error || 'Lookup failed') : pending());

// ---------- Card rendering ----------

function createCard(domain) {
  const steps = {};
  const stepsRow = el('div', { class: 'steps' });
  for (const s of STEPS) {
    steps[s] = el('span', { class: 'step', 'data-state': 'pending', text: STEP_LABELS[s] });
    stepsRow.append(steps[s]);
  }
  const badges = el('span', { class: 'card-title-badges' });
  const body = el('div', {}, el('div', { class: 'view-normal' }, el('span', { class: 'none', text: 'Scanning…' })));
  const root = el('article', { class: 'card' },
    el('div', { class: 'card-head' },
      el('div', { class: 'card-title' }, el('h2', { text: domain }), badges),
      stepsRow),
    body);

  return {
    root,
    setStep(step, state) { steps[step]?.setAttribute('data-state', state); },
    // Partial render while lookups are still arriving.
    update(r) {
      badges.replaceChildren(...buildBadges(r));
      body.replaceChildren(
        buildNormal(r),
        el('div', { class: 'card-body view-detailed' }, ...buildSections(r)),
      );
    },
    render(r) {
      for (const s of STEPS) if (steps[s].dataset.state === 'running' || steps[s].dataset.state === 'pending') steps[s].dataset.state = 'skip';
      badges.replaceChildren(...buildBadges(r));
      body.replaceChildren(
        buildNormal(r),
        el('div', { class: 'card-body view-detailed' }, ...buildSections(r)),
      );
    },
  };
}

function badge(text, cls) { return el('span', { class: `badge ${cls || ''}`, text }); }

function buildBadges(r) {
  const out = [];
  if (r.dns?.ok && r.dns.data.nxdomain) out.push(badge('NXDOMAIN', 'fail'));
  if (r.http?.ok) {
    const h = r.http.data;
    out.push(badge(`HTTP ${h.status}`, h.status < 400 ? 'ok' : 'warn'));
    if (h.crossDomain) out.push(badge(`Redirects → ${new URL(h.finalUrl).hostname}`, 'warn'));
    else if (h.redirected) out.push(badge(`${h.redirects.length} redirect${h.redirects.length > 1 ? 's' : ''}`, ''));
    if (h.metaRefresh) out.push(badge('Meta refresh', 'warn'));
    if (h.jsRedirect) out.push(badge('JS redirect?', 'warn'));
  } else if (r.http) {
    out.push(badge('Unreachable', 'fail'));
  }
  if (r.cdn) out.push(badge(`Behind ${r.cdn.name}`, ''));
  if (r.ssl?.ok && !r.ssl.data.found) out.push(badge('No SSL cert', 'warn detail-only'));
  const age = r.whois?.ok ? domainAge(r.whois.data.created) : null;
  if (age) out.push(badge(age.isNew ? `${age.label} (${age.days}d old)` : `Established · ${age.text}`, age.cls));
  return out;
}

// Normal view: registrar + hosting with abuse emails, and creation / modification dates.
const appendAll = (parent, ...nodes) => parent.append(...nodes.filter(Boolean));

function urlRow(label, url) {
  return el('div', { class: 'url-row' },
    el('span', { class: 'sub url-label', text: label }),
    el('span', { class: 'url-value mono', title: url }, safeLink(url)),
    copyBtn(url));
}

function urlBox(r) {
  const x = r.http?.ok ? r.http.data : null;
  const start = r.pageUrl || x?.requestedUrl || `https://${r.domain}/`;
  const rows = [urlRow(r.pageUrl ? 'Page URL' : 'URL', start)];
  if (x && x.finalUrl !== start && x.finalUrl !== x.requestedUrl) rows.push(urlRow('Redirects to', x.finalUrl));
  return el('div', { class: 'box urls' }, ...rows);
}

// Registrant contact published by the registry (e.g. .uy). Shown when there is no registrar abuse contact.
function registrantContact(w) {
  const reg = w.registrant || {};
  if (w.registrar.abuseEmail || !reg.email) return null;
  return el('div', { class: 'email' },
    el('div', { class: 'sub', text: `Registrant (domain owner)${reg.name ? `: ${reg.name}` : ''}` }),
    emailNode(reg.email));
}

function buildNormal(r) {
  const w = r.whois?.ok ? r.whois.data : null;
  const h = r.hosting?.ok ? r.hosting.data : null;

  const registrar = el('div', { class: 'box' }, el('h3', { text: 'Registrar' }));
  if (w) {
    appendAll(registrar,
      el('div', { class: 'name', text: w.registrar.name || 'Unknown registrar' }),
      w.registrar.ianaId ? el('div', { class: 'sub', text: `IANA ID ${w.registrar.ianaId}` }) : null,
      w.registrar.note ? el('div', { class: 'sub', text: w.registrar.note }) : null,
      w.registrar.abuseEmail || !w.registrant?.email ? el('div', { class: 'email' }, emailNode(w.registrar.abuseEmail)) : null,
      registrantContact(w),
      reportActions(r, w.registrar.name, w.registrar.abuseEmail),
    );
  } else {
    registrar.append(failOrPending(r.whois));
  }

  const hosting = el('div', { class: 'box' }, el('h3', { text: 'Hosting provider' }));
  if (h) {
    appendAll(hosting,
      el('div', { class: 'name', text: h.provider || 'Unknown provider' }),
      el('div', { class: 'sub', text: [h.asn, h.ip].filter(Boolean).join(' · ') }),
      el('div', { class: 'email' }, emailNode(h.abuseEmail)),
      reportActions(r, h.provider, h.abuseEmail),
      cdnNote(r, h),
    );
  } else {
    hosting.append(failOrPending(r.hosting));
  }

  const dateItem = (label, value) =>
    el('div', {}, el('span', { text: label }), value ? el('strong', { text: fmtDate(value) }) : none());
  const dates = el('div', { class: 'box dates' },
    el('div', { class: 'date-row' },
      dateItem('Created', w?.created),
      dateItem('Updated', w?.updated),
    ),
    w ? el('div', { class: 'age-row' }, el('span', { class: 'sub', text: 'Domain age' }), ageNode(w.created)) : null,
    el('div', { class: 'age-row' }, el('span', { class: 'sub', text: 'MX' }), mxLine(r)));

  return el('div', { class: 'view-normal' }, el('div', { class: 'summary' }, urlBox(r), registrar, hosting, dates));
}

function buildSections(r) {
  const out = [];

  // Registrar (WHOIS / RDAP)
  if (r.whois?.ok) {
    const w = r.whois.data;
    const reg = w.registrar;
    out.push(section('Registrar', 'abuse', kv([
      ['Registrar', reg.name],
      ['IANA ID', reg.ianaId],
      ['Note', reg.note || null],
      ['Abuse email', emailNode(reg.abuseEmail), 'email'],
      ['Abuse phone', reg.abusePhone],
      ['Website', reg.url ? safeLink(reg.url) : null],
      ['WHOIS server', reg.whoisServer],
    ]), reportActions(r, reg.name, reg.abuseEmail)));
  } else {
    out.push(section('Registrar', 'abuse', failOrPending(r.whois)));
  }

  // Hosting provider
  if (r.hosting?.ok) {
    const h = r.hosting.data;
    out.push(section('Hosting provider', 'abuse', kv([
      ['Provider', h.provider],
      ['ASN', h.asn],
      ['ISP', h.isp],
      ['IP owner (RDAP)', h.rdapOrg],
      ['Abuse email', emailNode(h.abuseEmail), 'email'],
      ['Abuse phone', h.abusePhone],
      ['Network', h.network ? [h.network.name, h.network.range].filter(Boolean).join(' · ') : null],
      ['Location', h.location],
      ['CDN / proxy', r.cdn ? r.cdn.name : 'None detected'],
    ]), reportActions(r, h.provider, h.abuseEmail), cdnNote(r, h)));
  } else {
    out.push(section('Hosting provider', 'abuse', failOrPending(r.hosting)));
  }

  // SSL certificate
  if (r.ssl?.ok) {
    const s = r.ssl.data;
    const names = s.dnsNames.slice(0, 10);
    out.push(section('SSL certificate', '', s.found ? kv([
      ['Issuer (CA)', s.issuer],
      ['Issued', fmtDate(s.issued)],
      ['Expires', fmtDate(s.expires)],
      ['Names covered', names.length ? el('ul', { class: 'list mono' },
        names.map((n) => el('li', { text: n })),
        s.sanCount > names.length ? el('li', { class: 'none', text: `+${s.sanCount - names.length} more` }) : null) : null],
      ['Active certs', `${s.activeCount}${s.activeCountTruncated ? '+' : ''}`],
      ['All issuers', s.issuers],
      ['Source', safeLink(s.link, `${s.source} · view on crt.sh ↗`)],
    ]) : el('div', {}, el('div', { class: 'error', text: 'No valid certificate in Certificate Transparency logs' }),
      safeLink(s.link, 'Check crt.sh ↗'))));
  } else {
    out.push(section('SSL certificate', '', failOrPending(r.ssl)));
  }

  // WHOIS details
  if (r.whois?.ok) {
    const w = r.whois.data;
    out.push(section('WHOIS', '', kv([
      ['Queried', w.queried !== r.domain ? `${w.queried} (registrable domain)` : w.queried],
      ['Created', fmtDate(w.created)],
      ['Domain age', ageNode(w.created)],
      ['Updated', fmtDate(w.updated)],
      ['Expires', fmtDate(w.expires)],
      ['Registrant', [w.registrant.name, w.registrant.org, w.registrant.country].filter(Boolean).join(', ') || null],
      ['Registrant email', w.registrant.email ? emailNode(w.registrant.email) : null],
      ['Registrant phone', w.registrant.phone || null],
      ['Source', w.viaWhois && w.source ? safeLink(w.source, w.source.replace(/^https?:\/\//, '')) : null],
      ['Status', w.status],
      ['DNSSEC', w.dnssec == null ? null : w.dnssec ? 'Signed' : 'Unsigned'],
      ['Nameservers', w.nameservers.length ? el('ul', { class: 'list mono' }, w.nameservers.map((n) => el('li', { text: n }))) : null],
    ])));
  }

  // IP + DNS
  const ipRows = [
    ['IP address', r.ip?.primary ? el('span', { class: 'mono', text: r.ip.primary }) : null],
    ['All IPs', r.ip?.all?.length > 1 ? el('span', { class: 'mono', text: r.ip.all.join(', ') }) : null],
    ['Connected IP', r.http?.ok && r.http.data.connectedIp ? el('span', { class: 'mono', text: r.http.data.connectedIp }) : null],
    ['MX record', mxLine(r)],
  ];
  const dnsContent = [kv(ipRows)];
  if (r.dns?.ok) {
    const grid = el('div', { class: 'dns-grid' });
    for (const [t, vals] of Object.entries(r.dns.data.records)) {
      grid.append(el('span', { class: 't', text: t }),
        vals.length ? el('span', { class: 'mono' }, vals.map((v) => el('div', { text: v }))) : none('—'));
    }
    dnsContent.push(el('details', { open: r.dns.data.nxdomain ? null : '' }, el('summary', { text: 'DNS records' }), grid));
    if (r.dns.data.nxdomain) dnsContent.push(errorLine('Domain does not exist (NXDOMAIN)'));
  } else {
    dnsContent.push(failOrPending(r.dns));
  }
  out.push(section('IP & DNS', '', ...dnsContent));

  // HTTP / redirects / title
  if (r.http?.ok) {
    const h = r.http.data;
    const chain = el('ol', { class: 'chain' });
    for (const hop of h.redirects) {
      chain.append(el('li', {}, el('span', { class: 'code', text: hop.status ?? '3xx' }), hop.from));
    }
    chain.append(el('li', {}, el('span', { class: 'code final', text: h.status }), h.finalUrl));

    out.push(section('HTTP, redirects & title', 'wide', kv([
      ['Page title', h.title],
      ['Page URL', r.pageUrl ? el('span', {}, safeLink(r.pageUrl), copyBtn(r.pageUrl)) : null],
      ['Requested URL', el('span', {}, safeLink(h.requestedUrl), copyBtn(h.requestedUrl))],
      ['Final URL', el('span', {}, safeLink(h.finalUrl), copyBtn(h.finalUrl))],
      ['Status', `${h.status} ${h.statusText || ''}`.trim()],
      ['Server', h.headers.server],
      ['Powered by', h.headers.poweredBy],
      ['Content type', h.headers.contentType],
      ['Redirect chain', chain],
      ['Meta refresh', h.metaRefresh ? safeLink(h.metaRefresh) : null],
      ['JS redirect', h.jsRedirect ? safeLink(h.jsRedirect) : null],
      ['Notes', h.attempts?.length ? h.attempts.join('; ') + ' (fell back)' : null],
    ])));
  } else {
    out.push(section('HTTP, redirects & title', 'wide', failOrPending(r.http)));
  }

  return out;
}

// ---------- Scan flow ----------

function parseInput(text) {
  const domains = text.split(/[\s,;]+/).map(normalizeDomain).filter(Boolean);
  return [...new Set(domains)].slice(0, MAX_DOMAINS);
}

async function pool(items, limit, fn) {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}

async function runScan({ fresh = false } = {}) {
  const domains = parseInput(input.value);
  if (!domains.length) {
    statusEl.textContent = 'Enter at least one valid domain.';
    return;
  }
  scanBtn.disabled = true;
  exportCsvBtn.disabled = exportJsonBtn.disabled = true;
  results.replaceChildren();
  lastResults = new Array(domains.length);

  const cards = domains.map((d) => {
    const c = createCard(d);
    results.append(c.root);
    return c;
  });

  let done = 0;
  statusEl.textContent = `Scanning ${domains.length} domain${domains.length > 1 ? 's' : ''}…`;
  await pool(domains, CONCURRENCY, async (d, i) => {
    const r = await scanDomain(d, {
      fresh,
      onStep: (step, state) => cards[i].setStep(step, state),
      onUpdate: (partial) => { partial.pageUrl ??= tabUrls.get(d) || null; cards[i].update(partial); },
    });
    r.pageUrl ??= tabUrls.get(d) || null;
    lastResults[i] = r;
    cards[i].render(r);
    done++;
    statusEl.textContent = `Scanned ${done} / ${domains.length}`;
  });

  statusEl.textContent = `Done — ${domains.length} domain${domains.length > 1 ? 's' : ''} scanned.`;
  scanBtn.disabled = false;
  exportCsvBtn.disabled = exportJsonBtn.disabled = false;
  try { await chrome.storage.local.set({ lastScan: { input: input.value, results: lastResults } }); } catch { /* ignore */ }
}

function renderSaved(saved) {
  input.value = saved.input || '';
  lastResults = saved.results || [];
  results.replaceChildren();
  for (const r of lastResults) {
    if (!r) continue;
    const c = createCard(r.domain);
    c.render(r);
    results.append(c.root);
  }
  if (lastResults.length) {
    statusEl.textContent = `Showing last scan (${new Date(lastResults[0].scannedAt).toLocaleString()})`;
    exportCsvBtn.disabled = exportJsonBtn.disabled = false;
  }
}

// ---------- Export ----------

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function toCsv(rows) {
  const cols = [
    'domain', 'page_url', 'registrar', 'registrar_iana_id', 'registrar_abuse_email', 'registrar_abuse_phone',
    'created', 'updated', 'expires', 'domain_age_days', 'new_domain', 'nameservers', 'ip', 'hosting_provider', 'asn', 'hosting_abuse_email',
    'hosting_abuse_phone', 'cdn', 'cdn_abuse_email', 'ssl_issuer', 'ssl_issued', 'ssl_expires', 'mx_exists', 'mx_records', 'http_status', 'final_url', 'redirected', 'redirect_chain', 'page_title', 'errors',
  ];
  const esc = (v) => {
    let s = v == null ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formulas
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(',')];
  for (const r of rows.filter(Boolean)) {
    const w = r.whois?.ok ? r.whois.data : null;
    const h = r.hosting?.ok ? r.hosting.data : null;
    const x = r.http?.ok ? r.http.data : null;
    const s = r.ssl?.ok && r.ssl.data.found ? r.ssl.data : null;
    const errors = [
      !r.whois?.ok && r.whois?.error, !r.dns?.ok && r.dns?.error,
      !r.http?.ok && r.http?.error, !r.hosting?.ok && r.hosting?.error, !r.ssl?.ok && r.ssl?.error,
    ].filter(Boolean).join(' | ');
    lines.push([
      r.domain, r.pageUrl, w?.registrar.name, w?.registrar.ianaId, w?.registrar.abuseEmail, w?.registrar.abusePhone,
      fmtDate(w?.created), fmtDate(w?.updated), fmtDate(w?.expires),
      domainAge(w?.created)?.days, w?.created ? (domainAge(w.created)?.isNew ? 'yes' : 'no') : '',
      w?.nameservers.join(' '), r.ip?.primary,
      h?.provider, h?.asn, h?.abuseEmail, h?.abusePhone,
      r.cdn?.name, r.cdn?.abuseEmail, s?.issuer, fmtDate(s?.issued), fmtDate(s?.expires),
      mxStatus(r)?.exists == null ? '' : mxStatus(r).exists ? 'yes' : 'no',
      mxStatus(r)?.hosts.map((h) => h.host).join(' '), x?.status, x?.finalUrl,
      x ? (x.redirected ? 'yes' : 'no') : '',
      x ? [...x.redirects.map((hop) => hop.from), x.finalUrl].join(' -> ') : '',
      x?.title, errors,
    ].map(esc).join(','));
  }
  return lines.join('\r\n');
}

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');

// ---------- Wire up ----------

scanBtn.addEventListener('click', () => runScan());
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runScan();
});

$('#clear').addEventListener('click', async () => {
  input.value = '';
  results.replaceChildren();
  lastResults = [];
  statusEl.textContent = '';
  exportCsvBtn.disabled = exportJsonBtn.disabled = true;
  try { await chrome.storage.local.remove('lastScan'); } catch { /* ignore */ }
});

async function currentTabHost() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const host = tab?.url && /^https?:/.test(tab.url) ? normalizeDomain(tab.url) : null;
  if (host) tabUrls.set(host, tab.url);
  return host;
}

$('#useTab').addEventListener('click', async () => {
  try {
    const host = await currentTabHost();
    if (!host) { statusEl.textContent = 'Current tab is not a website.'; return; }
    const existing = parseInput(input.value);
    if (!existing.includes(host)) input.value = [...existing, host].join('\n');
  } catch (e) {
    statusEl.textContent = `Could not read current tab: ${e.message}`;
  }
});

$('#openTab').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('popup.html?tab=1') });
  if (!document.body.classList.contains('full')) window.close();
});

exportCsvBtn.addEventListener('click', () => download(`domain-scan-${stamp()}.csv`, toCsv(lastResults), 'text/csv'));
exportJsonBtn.addEventListener('click', () =>
  download(`domain-scan-${stamp()}.json`, JSON.stringify(lastResults.filter(Boolean), null, 2), 'application/json'));

// On open: auto-scan the current tab's domain (popup only). Reuse a recent result
// for the same domain so reopening the popup is instant; otherwise show the last scan.
const CACHE_MS = 10 * 60 * 1000;

async function init() {
  // Read the saved scan and the current tab at the same time.
  const [saved, host] = await Promise.all([
    chrome.storage.local.get('lastScan').then((o) => o.lastScan || null, () => null),
    document.body.classList.contains('full') ? null : currentTabHost().catch(() => null),
  ]);

  if (host) {
    // Popup on a website: results only, no input panel.
    $('#inputPanel').hidden = true;
    const rescan = $('#rescan');
    rescan.hidden = false;
    rescan.addEventListener('click', async () => {
      input.value = host;
      rescan.disabled = true;
      await runScan({ fresh: true });
      rescan.disabled = false;
    });

    const cached = saved?.results?.length === 1 && saved.results[0]?.domain === host &&
      Date.now() - new Date(saved.results[0].scannedAt) < CACHE_MS;
    if (cached) {
      saved.results[0].pageUrl = tabUrls.get(host) || saved.results[0].pageUrl;
      renderSaved(saved);
    } else {
      input.value = host;
      runScan();
    }
    return;
  }
  if (saved) renderSaved(saved);
  input.focus();
}

init();
pruneCache();
