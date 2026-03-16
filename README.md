# Enterprise ASM Platform (Skeleton)

This repo provides a minimal foundation for an enterprise attack surface management
and vulnerability scanning platform. It maps directly to your requirements:

1. Asset Discovery (domain ingestion, subdomain discovery, service discovery, cloud assets, enrichment)
2. Vulnerability Scanning Engine (Subfinder/Amass/dnsx/httpx/naabu/katana/gau/Nuclei)
3. Data Processing / Analysis (dedupe, severity, risk scoring, correlation)
4. Continuous Monitoring (6h/weekly/monthly schedules)
5. Distributed Scanning (worker loop + DB-backed queue)
6. Data Storage (orgs/users/assets/scans/findings/alerts/asset_relationships/asset_history)
7. Dashboard (React UI + API endpoints)
8. Reporting (CSV + PDF summary exports)
9. Alerts & Notifications (email/slack/discord/webhook)
10. Multi-tenant (JWT + API key auth)
11. Security & Compliance (audit-ready models, encryption hooks)
12. Deployment (API backend + workers + scheduler)

## Quick Start

```bash
python -m venv .venv
./.venv/Scripts/activate
pip install -e .
uvicorn app.main:app --reload
```

Register an org + admin user:

```bash
curl -X POST http://127.0.0.1:8000/auth/register -H "Content-Type: application/json" -d "{\"org_name\":\"Acme\",\"email\":\"admin@acme.com\",\"password\":\"change-me-now\"}"
```

Use the returned token for all requests:

```bash
curl -X POST http://127.0.0.1:8000/assets/ingest -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"domain\":\"example.com\",\"environment\":\"prod\"}"
```

Create a scan:

```bash
curl -X POST http://127.0.0.1:8000/scans -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"scan_type\":\"vuln\"}"
```

Secret scan (GitHub/GitLab/trufflehog):

```bash
curl -X POST http://127.0.0.1:8000/scans -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"scan_type\":\"secret\"}"
```

Check dashboard overview:

```bash
curl http://127.0.0.1:8000/dashboard/overview -H "Authorization: Bearer <token>"
```

Asset inventory APIs:

```bash
curl http://127.0.0.1:8000/assets -H "Authorization: Bearer <token>"
curl http://127.0.0.1:8000/services -H "Authorization: Bearer <token>"
curl http://127.0.0.1:8000/vulnerabilities -H "Authorization: Bearer <token>"
curl http://127.0.0.1:8000/changes -H "Authorization: Bearer <token>"
curl http://127.0.0.1:8000/assets/history -H "Authorization: Bearer <token>"
```

Run a worker in another terminal to process scans:

```bash
python -m app.tasks.worker
```

Optionally run the scheduler (6h/daily/weekly):

```bash
python -m app.tasks.scheduler
```

Run the React dashboard (optional):

```bash
cd frontend
npm install
npm run dev
```

Run the Next.js dashboard (optional):

```bash
cd frontend-next
npm install
npm run dev
```

## Notes

- Scanner pipeline: domain -> passive (subfinder/amass) -> active intel (chaos/pdns/censys/securitytrails/dnsdumpster/shodan/cloudflare) -> certificate (crt.sh/certspotter/google-ct) -> dns brute (wordlist/cmd/puredns/massdns) -> subdomain permutations -> JS subdomain extraction -> reverse IP -> ASN/range expansion -> cloud asset discovery (buckets/CDN) -> enrichment (asn/hosting/cdn/country) -> dnsx -> httpx -> naabu -> katana/gau/waybackurls/ffuf/dirsearch -> nuclei.
- Scanner integrations call real CLI binaries (Subfinder/Amass/chaos/dnsx/httpx/naabu/katana/gau/waybackurls/Nuclei) plus optional command templates.
  Make sure these are installed and in PATH or set `ASM_*_BIN` env vars.
- Asset intelligence: cert transparency discovery, certspotter, passive DNS (`ASM_PDNS_CMD`), Censys host intel
  (`ASM_CENSYS_CMD`), DNS brute (`ASM_DNS_BRUTE_CMD`), puredns (`ASM_PUREDNS_CMD`), massdns (`ASM_MASSDNS_CMD`),
  reverse IP (`ASM_REVERSE_IP_CMD`), ASN/IP enrichment (`ASM_ASN_CMD`, `ASM_ASN_RANGES_CMD`, `ASM_GEOIP_CMD`),
  SecurityTrails (`ASM_SECURITYTRAILS_CMD`), Shodan (`ASM_SHODAN_CMD`), cloud bucket probing,
  DNS misconfig detection (A/AAAA/CNAME/MX/NS/TXT), subdomain takeover checks (Nuclei takeover templates),
  GitHub/GitLab code search, and optional secret scanning via `trufflehog` (GitHub org/repo or
  `ASM_PUBLIC_REPO_URL`) plus endpoint secret scans.
- Configure optional scanner args via `ASM_SUBFINDER_ARGS`, `ASM_AMASS_ARGS`,
  `ASM_CHAOS_ARGS`, `ASM_DNSX_ARGS`, `ASM_HTTPX_ARGS`, `ASM_NAABU_ARGS`, `ASM_KATANA_ARGS`,
  `ASM_GAU_ARGS`, `ASM_WAYBACKURLS_ARGS`, `ASM_FFUF_ARGS`, `ASM_DIRSEARCH_ARGS`, `ASM_NUCLEI_ARGS`.
- `ASM_HTTPX_TECH_DETECT` toggles technology detection in httpx (default true).
- Set `ASM_JWT_SECRET` in production.
- Cert transparency can be disabled with `ASM_CT_ENABLED=false`.
- Scan rate limiter: `ASM_SCAN_RATE` (requests per second, 0 disables).
- Scheduler intervals: `ASM_ASSET_SCAN_INTERVAL_HOURS` (default 6),
  `ASM_VULN_SCAN_INTERVAL_DAYS` (default 1), `ASM_DEEP_SCAN_INTERVAL_DAYS` (default 7).
- Alerts: set `ASM_ALERTS_ENABLED=true`, `ASM_SLACK_WEBHOOK`,
  `ASM_DISCORD_WEBHOOK`, `ASM_ALERT_WEBHOOK`, and SMTP settings for email.
- Jira integration: set `ASM_JIRA_ENABLED=true`, `ASM_JIRA_BASE`, `ASM_JIRA_EMAIL`,
  `ASM_JIRA_TOKEN`, `ASM_JIRA_PROJECT`, and optional `ASM_JIRA_ISSUE_TYPE`.
- Cloud public checks can be toggled with `ASM_CLOUD_PUBLIC_CHECK` (default true).
- For Redis queueing, set `ASM_QUEUE_BACKEND=redis` and `REDIS_URL`.
- For worker scale (10/50/100), run multiple worker processes/containers against the Redis queue.
- The DB queue design is intended for single-worker dev use.
- Worker modes: `ASM_WORKER_MODE=discovery|vuln|secret|all` to run specialized discovery or vuln clusters.
- The API is intentionally minimal; add quotas, SSO, and advanced UI endpoints as needed.
- Continuous monitoring includes asset diff snapshots (`asset_changes`) with alerts for new assets/ports/endpoints.
- Risk scoring: severity weights (critical 80/high 50/medium 20/low 5/info 1) plus exposure bonus and asset importance.

Optional intel configuration:

- `ASM_PDNS_CMD` and `ASM_CENSYS_CMD` accept a shell-style command template with `{domain}`.
- `ASM_DNS_BRUTE_CMD` accepts a shell-style command template with `{domain}` (use puredns/shuffledns/etc).
- `ASM_DNS_BRUTE_WORDLIST` and `ASM_DNS_BRUTE_LIMIT` tune brute-force size.
- `ASM_PUREDNS_CMD` accepts a shell-style command template with `{domain}`.
- `ASM_MASSDNS_CMD` accepts a shell-style command template with `{domain}`.
- `ASM_CERTSPOTTER_ENABLED`, `ASM_CERTSPOTTER_TOKEN`, and `ASM_CERTSPOTTER_LIMIT` tune certspotter CT.
- `ASM_REVERSE_IP_CMD` accepts a shell-style command template with `{ip}` and `ASM_REVERSE_IP_LIMIT` caps lookups.
- `ASM_REVERSE_IP_INCLUDE_EXTERNAL=true` allows reverse IP to include non-owned domains for intel graphing.
- `ASM_SHODAN_CMD`, `ASM_SECURITYTRAILS_CMD`, and `ASM_DNSDUMPSTER_CMD` accept a shell-style command template with `{domain}`.
- `ASM_CLOUDFLARE_CMD` accepts a shell-style command template with `{domain}`.
- `ASM_ASN_CMD`, `ASM_HOSTING_CMD`, and `ASM_GEOIP_CMD` accept a shell-style command template with `{ip}` for IP enrichment.
- `ASM_ASN_RANGES_CMD` accepts a shell-style command template with `{asn}` and `ASM_ASN_RANGE_LIMIT` caps range fetches.
- `ASM_ASN_DISCOVERY_ENABLED` and `ASM_IP_RANGE_SCAN_LIMIT` tune ASN/IP range expansion.
- `ASM_BUCKET_WORDLIST`, `ASM_BUCKET_WORDS`, `ASM_BUCKET_LIMIT`, `ASM_BUCKET_PROBE_TIMEOUT` tune cloud bucket probing.
- `ASM_CLOUD_ENUM_ENABLED` toggles bucket probing.
- `ASM_JS_MAX_BYTES`, `ASM_JS_URL_LIMIT`, `ASM_JS_SUBDOMAIN_LIMIT` tune JS subdomain extraction.
- `ASM_PERMUTATION_WORDS`, `ASM_PERMUTATION_LIMIT` tune subdomain permutations.
- `ASM_RECURSIVE_ENABLED`, `ASM_RECURSIVE_MAX_DEPTH`, `ASM_RECURSIVE_MAX_NEW` tune recursive discovery.
- `ASM_GITHUB_SEARCH_QUERY` and `ASM_GITHUB_SEARCH_LIMIT` tune GitHub code search.
- `ASM_GITLAB_SEARCH_QUERY` and `ASM_GITLAB_SEARCH_LIMIT` tune GitLab code search.
- `ASM_BITBUCKET_CMD`, `ASM_BITBUCKET_SEARCH_QUERY`, and `ASM_BITBUCKET_SEARCH_LIMIT` tune Bitbucket search.
- `ASM_PUBLIC_REPO_URL` enables public repository secret scanning (trufflehog).
- `ASM_SECRET_SCAN_LIMIT`, `ASM_SECRET_MAX_BYTES`, `ASM_SECRET_REGEX` tune endpoint secret scanning.
- `ASM_FFUF_WORDLIST`, `ASM_FFUF_WORDS`, `ASM_FFUF_LIMIT` tune endpoint fuzzing.
- `ASM_DIRSEARCH_WORDLIST`, `ASM_DIRSEARCH_WORDS`, `ASM_DIRSEARCH_LIMIT`, `ASM_DIRSEARCH_RATE`, `ASM_DIRSEARCH_TIMEOUT` tune dirsearch fuzzing.
