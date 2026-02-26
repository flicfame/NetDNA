# NetDNA - Network Security Monitoring Platform

## Overview

NetDNA is a network security monitoring and analytics platform built as a full-stack TypeScript application. It simulates enterprise network traffic data (NetFlow, VPN sessions, wireless clients, OT/SCADA devices, NAC shim fleet) and provides a dashboard for security analysts to monitor anomalies, manage alerts, visualize network topology, and operate Edge NAC shims for OT micro-segmentation. The application uses static HTML pages served from `public/` for the main UI alongside a React SPA scaffold for future development.

**Phase 1 Focus**: Prove the NAC Shim can safely extend enforceable identity-based micro-segmentation to legacy OT devices without breaking production. Operational lifecycle: shim boots → registers → gets approved → discovers downstream → logs violations → enforces/contains.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Dual Frontend Architecture
- **Primary UI**: Static HTML pages in `public/pages/` with vanilla JavaScript (`public/assets/js/app.js`) for API calls and DOM manipulation. Cisco-branded, enterprise-styled pages with shared CSS (`public/assets/css/shared.css`).
  - Core pages: login, dashboard, topology, remote, ot, heatmap, prediction, quarantine, users, api-docs, testlab, mynetwork
  - Edge NAC pages: shim-devices, shim-downstream, shim-policies, shim-ise
- **Secondary UI (scaffold)**: A React + Vite SPA in `client/src/` using shadcn/ui components, Tailwind CSS, wouter for routing, and TanStack React Query. Currently unused — exists as infrastructure for future development.
- **UI Components**: Full shadcn/ui (new-york style) component library installed in `client/src/components/ui/`.

### Backend Architecture
- **Runtime**: Node.js with Express, written in TypeScript, executed via `tsx`
- **API Pattern**: RESTful API under `/api/v1/` prefix. Routes defined in `server/routes.ts`
- **Authentication**: JWT-based auth (not session-based). Tokens created with `jsonwebtoken`, passwords hashed with `bcryptjs`. Role-based access control with three roles: `admin`, `analyst`, `viewer`, each with defined permission sets
- **Auth middleware**: `authMiddleware` extracts JWT from `Authorization: Bearer` header. `requirePermission()` and `requireAdmin()` guard specific endpoints
- **Rate limiting**: Login endpoint has in-memory rate limiting (10 attempts/minute/IP)
- **Data Simulator**: `server/simulator/` (modular) generates realistic network data and inserts it into the database on a timer. Runs every 5s; edge/propagation/correlator tick every 30s

### Operating Modes (`NETDNA_MODE` env var)
- **`sim`** (default): Full simulator runs, default credentials created, dev-friendly
- **`live`**: Simulator disabled, requires `SESSION_SECRET` and `ADMIN_PASSWORD` env vars, no demo users created
- **`hybrid`**: Simulator runs alongside real connectors (future), requires production credentials

### Database
- **PostgreSQL** via `pg` (node-postgres) connection pool
- **ORM**: Drizzle ORM with PostgreSQL dialect
- **Schema**: Defined in `shared/schema.ts` using Drizzle's `pgTable` helpers. Key tables:
  - `users` — app users with roles and hashed passwords
  - `flows` — network flow records (NetFlow-style)
  - `entities` — network entities (devices/users on the network)
  - `anomalies` — detected security anomalies
  - `vlans` — VLAN definitions
  - `vpnSessions` — VPN connection records
  - `wirelessClients` — wireless client records
  - `accessPoints` — wireless access points
  - `otDevices`, `otEvents`, `otProcessValues`, `otTraffic` — OT/SCADA related tables
  - `entityEdges` — durable relationship graph (FLOW, SAME_VLAN, USER_BINDING, OT_BOUNDARY, AP_ASSOCIATION edge types)
  - `episodes` — correlated attack narratives (intent, confidence, status, primary entity)
  - `episodeAnomalies` — join table linking episodes to their constituent anomalies
  - **NAC Shim tables** (Phase 1):
    - `shims` — shim devices (shim_id PK, name, site_id, zone, status, mode, firmware, interfaces, cert, heartbeat)
    - `downstreamDevices` — OT devices discovered behind shims (mac, ip, type, template, ISE group)
    - `policyTemplates` — policy rule templates (plc, hmi, quarantine, rtu, historian, unknown built-in; custom allowed)
    - `shimPolicies` — shim-to-template assignments with mode and contain-safe config
    - `shimHealth` — time-series health metrics (CPU, memory, bridge latency, link status)
    - `shimViolations` — policy violation events with severity and MITRE technique
    - `shimFlows` — flow records through shim bridge
    - `iseSyncLog` — ISE synchronization audit trail
    - `shimAuditLog` — all shim configuration changes with actor
    - `newTalkers` — ARP/new-host discovery events (shim_id, ts, src_ip, dst_ip, dst_port, proto)
    - `enrollmentTokens` — bootstrap enrollment tokens (token_hash PK, shim_id, expiry, usage tracking, cert fingerprint)
- **Migrations**: Managed via `drizzle-kit push` (schema push, not migration files). Config in `drizzle.config.ts`
- **Seeding**: `seedDefaultUsers()` and `seedPolicyTemplates()` called at startup

### Build System
- **Development**: `tsx server/index.ts` runs the server, Vite dev server middleware handles HMR for the React client
- **Production Build**: Custom `script/build.ts` uses Vite to build the client and esbuild to bundle the server
- **Static Serving**: In production, `server/static.ts` serves the built Vite output from `dist/public` with SPA fallback

### Path Aliases
- `@/*` → `client/src/*`
- `@shared/*` → `shared/*`
- `@assets` → `attached_assets/`

### Intelligence Engine (`server/routes/intelligence.ts`)
Core behavioral analytics engine providing four capabilities:
- **Risk Propagation** (`GET /api/v1/intelligence/risk-propagation`)
- **Attack Chain Correlation** (`GET /api/v1/intelligence/attack-chains`)
- **Entity Graph** (`GET /api/v1/intelligence/entity-graph/:ip`)
- **Integration Status** (`GET /api/v1/intelligence/integration-status`)

### Episodes API (`server/routes/episodes.ts`)
- `GET /api/v1/episodes` — list correlated attack episodes with anomaly counts
- `GET /api/v1/episodes/:id` — full episode detail with linked anomalies

### Edge NAC Shim APIs (Phase 1)

#### Shim Fleet (`server/routes/shims.ts`)
- `GET /api/v1/shims` — list all shims with health summary
- `GET /api/v1/shims/stats` — fleet stats (total, online, pending, contained, violations_24h, shadow_events_24h)
- `GET /api/v1/shims/:shimId` — full detail with health, downstream, violations, policy
- `POST /api/v1/shims/register` — register new shim (pending state)
- `POST /api/v1/shims/:shimId/approve` — approve pending shim
- `POST /api/v1/shims/:shimId/heartbeat` — update health metrics
- `POST /api/v1/shims/:shimId/mode` — change mode (monitor/enforce/contain)
- `POST /api/v1/shims/:shimId/contain/clear` — release from contain
- `GET /api/v1/shims/:shimId/policy` — current policy with rules + hash
- `GET /api/v1/shims/:shimId/violations` — violations for a shim
- `GET /api/v1/shims/:shimId/audit` — audit log
- `POST /api/v1/shims/:shimId/downstream` — report discovered downstream device
- `POST /api/v1/telemetry` — ingest violation + flow + new_talker batches
- `GET /api/v1/shims/:shimId/new-talkers` — new-talker discovery events for a shim (default 7 days)

#### Downstream Devices (`server/routes/downstream.ts`)
- `GET /api/v1/downstream` — list all downstream devices across shims
- `GET /api/v1/downstream/:deviceId` — single device detail
- `PATCH /api/v1/downstream/:deviceId` — tag/classify device
- `GET /api/v1/downstream/:deviceId/history` — violation history for device

#### Policies (`server/routes/policies.ts`)
- `GET /api/v1/policies/templates` — list all policy templates
- `GET /api/v1/policies/templates/:name` — single template with rules
- `PATCH /api/v1/policies/templates/:name` — update template
- `POST /api/v1/policies/templates` — create custom template
- `POST /api/v1/shims/:shimId/policy/assign` — assign template to shim
- `GET /api/v1/policies/assignments` — all shim→template assignments

#### ISE Integration (`server/routes/ise.ts`)
- `GET /api/v1/ise/status` — ISE connection status (stub in sim mode)
- `GET /api/v1/ise/log` — ISE sync log
- `POST /api/v1/ise/sync` — trigger ISE sync (stub in sim mode)
- `GET /api/v1/violations/summary` — fleet-wide violation summary
- `POST /api/v1/ise/writeback/:deviceId` — ISE writeback (stub in sim mode, returns 503)

#### Enrollment (`server/routes/enroll.ts`)
- `POST /api/v1/enroll` — certificate enrollment (stub in sim mode, returns 503; use netdna-core with mTLS in production)

### Simulator Modules (`server/simulator/`)
- `flows.ts` — NetFlow traffic generation
- `remote.ts` — VPN/wireless client simulation
- `ot.ts` — OT/SCADA device and event simulation
- `edges.ts` — Entity edge population (FLOW and SAME_VLAN relationships)
- `propagation.ts` — Risk score propagation through entity_edges
- `correlator.ts` — Episode correlator (groups anomalies into attack narratives)
- `shims.ts` — NAC shim fleet simulator: seeds 7 shims across 3 sites, 14 downstream OT devices, 6 built-in policy templates; ticks health metrics, violations, flows, and new-talker discovery events every 5s

### Edge NAC Pages
- **shim-devices.html** — Fleet overview with stats strip, shim table, approve/mode-change workflows, detail drawer with tabs (Overview, Violations, Policy, Downstream, Health)
- **shim-downstream.html** — All downstream OT devices with filtering, tag/classify modal, violation history, CSV export
- **shim-policies.html** — Policy template cards with expandable rule lists, assignment table, assign-template action
- **shim-ise.html** — ISE connection status, sync log, violation summary with KPIs and charts, trigger sync button
- All pages share a sub-header navigation bar linking to each other

### Utilities
- `server/utils.ts` — `toSnakeCase()` / `toSnakeCaseArray()` helpers for API response serialization

### Key Design Decisions
1. **JWT over sessions**: Chosen for stateless API auth. Tokens expire after 8 hours. Client stores token in localStorage.
2. **Static HTML + vanilla JS for main pages**: Fully self-contained HTML files with inline styles/scripts for rapid prototyping of Cisco-branded enterprise UI.
3. **Simulated data**: Simulator modules create realistic-looking network security data for demo/prototype purposes.
4. **Shared schema**: The `shared/` directory contains the Drizzle schema used by both server and client for type safety.
5. **Graph-on-relational**: Entity relationships modeled through PostgreSQL `entity_edges` table with edge types and weights.
6. **Episode-based correlation**: Anomalies automatically grouped into narrative "episodes" by the correlator.
7. **NAC Shim architecture mirrors netdna-core**: The shim tables and APIs are designed to match the separate Python/FastAPI `netdna-core` control plane, enabling future integration where the Node.js app acts as the UI/API gateway and netdna-core handles the shim control protocol.

## External Dependencies

### Database
- **PostgreSQL**: Required. Connection via `DATABASE_URL` environment variable. Used through `pg` pool + Drizzle ORM.

### Environment Variables
- `DATABASE_URL` — PostgreSQL connection string (required)
- `SESSION_SECRET` — JWT signing secret (falls back to `"netdna-dev-secret"` in sim mode; required in live/hybrid)
- `NETDNA_MODE` — Operating mode: `sim` (default), `live`, `hybrid`
- `ADMIN_PASSWORD` — Admin password override (required in live/hybrid mode)

### Key NPM Packages
- **Server**: Express, jsonwebtoken, bcryptjs, drizzle-orm, pg, connect-pg-simple
- **Client**: React 18, Vite, TanStack React Query, wouter, shadcn/ui (Radix UI primitives), Tailwind CSS, recharts, react-hook-form + zod
- **Build**: esbuild, tsx, drizzle-kit

### External Services
- No external APIs currently integrated
- No external authentication providers — fully self-contained JWT auth
