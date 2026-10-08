# Domain Scanner (Chrome extension)

Pipeline per domain: **WHOIS → DNS → HTTP → Redirect detection → Page title → IP → Registrar & Hosting provider (with abuse emails)**.

## Install
1. Open `chrome://extensions`, enable **Developer mode**.
2. Click **Load unpacked** and select this folder.
3. Pin the extension and click it. Use **Open in tab ↗** for bulk scans (a popup closes when it loses focus).

## Data sources (no API keys needed)
| Step | Source |
|---|---|
| WHOIS / registrar + abuse contact | RDAP via IANA bootstrap (`data.iana.org/rdap/dns.json`), registrar RDAP follow-up, `rdap.org` fallback |
| WHOIS fallback for TLDs without RDAP | `.uy`: NIC Uruguay public lookup (no separate registrar; shows registrant contact). Others: who-dat.as93.net (best effort) |
| DNS (A, AAAA, CNAME, MX, NS, TXT) | Google DNS-over-HTTPS, Cloudflare fallback |
| HTTP, redirect chain, title | Direct `fetch` (HTTPS then HTTP); redirect hops captured with `chrome.webRequest`; meta-refresh and JS redirects detected in the HTML |
| SSL certificate | Certificate Transparency logs via Cert Spotter API, crt.sh fallback |
| CDN / proxy detection | Response headers, CNAME targets and ASN (Cloudflare, Akamai, Fastly, CloudFront, Azure, Imperva, Sucuri, DDoS-Guard, Bunny, StackPath) |
| Hosting provider + abuse contact | IP RDAP (ARIN → auto-redirects to RIPE/APNIC/LACNIC/AFRINIC), ASN/ISP/location from `ipwho.is` |

## Features
- **Normal view** (default): registrar, hosting provider, both abuse emails, created & updated dates. **Detailed view**: full WHOIS, DNS, HTTP, redirect chain, title, network info. The choice is remembered.
- Clicking the icon automatically scans the current tab's domain (results cached for 10 minutes; press **Scan** to refresh)
- Multiple domains/URLs at once (newline, comma or space separated), "Use current tab"
- MX check: shows whether the domain has an MX record (mail servers listed), no MX, or a null MX (`0 .`, accepts no email)
- Domain age: **Very new** (<30 days), **New** (<90 days) or **Established**, shown in both views and exported to CSV
- Flags: NXDOMAIN, unreachable, cross-domain redirect, meta refresh, JS redirect
- **Report** button: opens a pre-filled abuse email (domain, URL, IP, registrar, host, CDN, creation date, SSL, title, redirect chain) to the registrar, host or CDN; **Copy report** for web abuse forms
- CDN warning when the real host is hidden, with the CDN abuse contact / form
- Export CSV / JSON; last scan is restored when reopening

## Performance
- Results render progressively as each lookup finishes; hosting starts as soon as the A record arrives.
- WHOIS guesses the registrable domain first (e.g. `a.b.example.co.uk` → `example.co.uk`) and only queries the registrar's RDAP when the registry response lacks the abuse contact.
- Cached in `chrome.storage.local`: WHOIS 24h, hosting 24h (per /24), SSL 6h, RDAP bootstrap 24h. DNS and HTTP are always live. **Rescan** bypasses the cache.
- Bulk scans run 6 domains in parallel.
- IANA bootstrap files are bundled in `data/` so the first scan never waits on them (refreshed in the background every 24h).
- IP ownership is queried from the mapped regional registry and ARIN in parallel; the first answer wins.
- DNS queries race Google and Cloudflare DNS-over-HTTPS and use whichever answers first.
- Page download stops shortly after `</head>` (title, meta refresh and redirect scripts live there).
- Connections to the lookup services are pre-opened when the popup loads.
- When Cert Spotter's hourly quota runs out, it is skipped for 30 minutes and crt.sh is used directly.

## Limitations
- Some ccTLDs have no public RDAP service, so WHOIS shows "not found" for them.
- Registrant data is usually redacted (GDPR); registrar and abuse contacts are not.
- `ipwho.is` is rate-limited on the free tier; provider falls back to the RDAP owner name.
- Cert Spotter allows ~100 unauthenticated requests/hour (large domains use up to 5); the extension falls back to crt.sh, which is slower.
- The certificate shown is the most recently issued valid one in CT logs, not necessarily the exact one the server presents (Chrome doesn't expose TLS details to extensions).
