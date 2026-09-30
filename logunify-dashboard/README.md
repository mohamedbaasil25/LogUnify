# LogUnify SOC Console (Next.js)

Dark-mode analyst dashboard for the LogUnify backend (`../logunify-backend`).

- **Metric cards**: ingestion rate (EPS + 60 s sparkline), anomaly count, noise reduced %, blockchain anchor status
- **Live log stream**: timestamp, source IP + GeoIP badge, log source, ECS `event.action`, anomaly severity, ATT&CK tag; search, severity filter, pause, click a row's chevron for the full ECS JSON and Drain3 template
- **Log Source Configurator** (Add source): Syslog / HTTP push / API pull without code
- **Threat-intel matches**: red `TI` badge on rows that hit a MISP/IOC indicator (severity escalates to at least High), a "Threat-intel matches" filter, and an IOC/hit counter in the header
- **Ledger verification**: load a record + Merkle proof from a sealed batch, edit it to simulate tampering, verify against the anchored root, or audit the whole batch

Stack: Next.js 15 (App Router), React 19, Tailwind CSS 3, lucide-react. No external fonts or CDNs.

## Run
```bash
# 1. backend (port 8000)
cd ../logunify-backend && python -m uvicorn app.main:app

# 2. dashboard (port 3000)
npm install
npm run dev
```
`next.config.mjs` proxies `/api/*` to `LOGUNIFY_API_URL` (default `http://localhost:8000`), so the browser never talks to the backend directly and no CORS setup is needed. Copy `.env.example` to `.env.local` to change it.

Scripts: `npm run dev`, `npm run build`, `npm run typecheck`.

## How the numbers are defined
| Card | Source |
|---|---|
| Ingestion rate | `throughput_eps["10s"]` from `GET /api/v1/metrics`; sparkline from `/metrics/throughput` |
| Anomaly count | events scored above 0.70 by the Isolation Forest |
| Noise reduced | `1 − distinct Drain3 templates / processed events` |
| Blockchain anchor | latest sealed Merkle batch and its (mock) Fabric receipt from `/integrity/batches` |

Severity badge from the anomaly score: `< 0.4` low, `0.4–0.7` medium, `> 0.7` high, `≥ 0.9` critical, "learning" until the model has warmed up.

## Source Configurator behaviour
- **HTTP push** is fully functional: saving returns an ingest URL and a secret token (shown once). Send logs with `X-Source-Token`; the source's `received` counter updates in the list.
- **Syslog** and **API pull** are stored as configuration with status `registered`; this build does not yet open the syslog listener or poll the API, and the UI says so.
- API URLs must be `https://` and cannot point at loopback/private hosts.

## Not production-ready yet
- **No authentication or roles.** Anyone who can reach the console can add/delete sources. Put it behind SSO/RBAC before exposing it.
- The stream polls every 2 s; use SSE/WebSocket for real deployments.
- GeoIP (deterministic demo data), ATT&CK IDs (placeholder mapping) and the Fabric ledger (in-memory mock) are not real intelligence.
- Source registry and anchors are in memory and vanish when the backend restarts.
- The narrow-screen table scrolls horizontally rather than collapsing into cards.
