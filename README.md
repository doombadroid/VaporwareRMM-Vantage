# VaporwareRMM Vantage

The federation control server for [VaporwareRMM Edge](https://github.com/doombadroid/VaporwareRMM-Edge) deployments.

Vantage is optional. VaporwareRMM Edge runs fully standalone for home users, self-hosters, and MSPs not doing federation.

## Status

F1 skeleton landed. Federation protocol comes in F2–F8. Treat this as **alpha-of-alpha** — do not point it at real customer fleets yet. See [`docs/PRODUCTION.md`](docs/PRODUCTION.md) for the production-readiness checklist (target: F8).

## What this is

Vantage is the master / control plane for MSPs operating multiple customer sites via VaporwareRMM Edge appliances. Each customer site runs an Edge instance that manages endpoints locally; Vantage aggregates state, routes operator actions, and provides the MSP a single pane of glass across all sites.

- **Edge appliances** stay on the customer LAN. Endpoint data lives there.
- **Vantage** aggregates status, routes commands, holds the audit checkpoint exchange.
- Endpoints **do not run Tailscale** in the federation model. Tailscale only tunnels Edge ↔ Vantage. See [doombadroid/VaporwareRMM-Edge#18](https://github.com/doombadroid/VaporwareRMM-Edge/issues/18) for the rationale.

## Quick start (Docker, Linux)

```bash
git clone https://github.com/doombadroid/VaporwareRMM-Vantage /srv/vantage
cd /srv/vantage

# 1. Generate secrets + fill .env
cp .env.example .env
POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -base64 48)
SECRETS_ENCRYPTION_KEY=$(openssl rand -base64 32)
ADMIN_PASSWORD='YourStrongPw!2026'    # >=12 chars, upper/lower/digit/special
VANTAGE_PUBLIC_URL='https://vantage.yourtailnet.ts.net'   # tailnet-routable URL Edges reach Vantage at
sed -i \
  -e "s|POSTGRES_PASSWORD=__GENERATE_ME__|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" \
  -e "s|JWT_SECRET=__GENERATE_ME__|JWT_SECRET=$JWT_SECRET|" \
  -e "s|SECRETS_ENCRYPTION_KEY=__GENERATE_ME__|SECRETS_ENCRYPTION_KEY=$SECRETS_ENCRYPTION_KEY|" \
  -e "s|ADMIN_PASSWORD=__GENERATE_ME__|ADMIN_PASSWORD=$ADMIN_PASSWORD|" \
  -e "s|VANTAGE_PUBLIC_URL=__GENERATE_ME__|VANTAGE_PUBLIC_URL=$VANTAGE_PUBLIC_URL|" \
  .env

# 2. Boot
docker compose up -d

# 3. Verify
curl -s http://localhost/health
# → {"status":"ok"}
```

Vantage refuses to boot if any required secret is left as `__GENERATE_ME__`. The sentinel-refusal pattern is intentional — copy-paste from `.env.example` without filling values fails loudly rather than landing a silently-default account.

Open `http://localhost` in a browser, log in as `admin@vaporrmm-vantage.local` with the `ADMIN_PASSWORD` you set.

## Required environment variables

| Var | Required | Notes |
|-----|----------|-------|
| `POSTGRES_PASSWORD` | yes | Postgres user `vantage`. Generated once, never rotated by the app. |
| `JWT_SECRET` | yes | ≥32 characters. HS256 over a short secret is forgeable; Vantage refuses to boot with <32. |
| `SECRETS_ENCRYPTION_KEY` | yes | 32 bytes, base64-encoded. AES-256-GCM key for the encrypted-secrets column path. |
| `ADMIN_PASSWORD` | yes (first run) | First-run admin user. After bootstrap, can be removed from the env file. |
| `CORS_ORIGINS` | no | Comma-separated. Empty blocks all cross-origin browser requests. Set in dev when the dashboard runs on a different origin. |
| `DOMAIN` | no | Caddy hostname. Default `localhost`. |
| `ACME_EMAIL` | no | Let's Encrypt contact. Required if `DOMAIN` is a real public name. |
| `BIND_ADDR` | no | Caddy publishes on this address. Default `127.0.0.1` (Tailscale-only access); `0.0.0.0` for public. |
| `VANTAGE_PORT` | no | Override the internal :9090 port. Useful only for non-compose deployments. |
| `VANTAGE_PUBLIC_URL` | yes | External URL operators reach Vantage at — embedded in enrollment bundles + used for the cookie-secure sanity check. Must have scheme + host (e.g. `https://vantage.yourtailnet.ts.net`). Must be `https://` unless `FORCE_SECURE_COOKIES=false`. Vantage refuses to start on invalid values. |
| `FORCE_SECURE_COOKIES` | no | Default `true`. Set `false` only for local-dev iteration over `http://localhost`. Combination of `false` + `https://` `VANTAGE_PUBLIC_URL` is rejected at boot — that combination would leak auth cookies cleartext. |
| `MINIMUM_REQUIRED_EDGE_VERSION` | no | Floor for federated Edge handshake. Empty = no floor. Must be a valid semver (e.g. `0.1.0` or `v0.1.0`) — invalid values are rejected at boot. |
| `TRUSTED_PROXIES` | no (yes behind a proxy) | CSV of CIDRs/IPs whose `X-Forwarded-For` Fiber will trust for `c.IP()`. Required for per-IP rate limiting to work behind Caddy. Default `127.0.0.1/32` for co-located Caddy in compose. Unset = no proxy trust + warning logged at startup. |

## Quick start (dev, no Docker)

```bash
# 1. Postgres
docker run --rm -d --name vantage-pg \
  -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine

# 2. Vantage server
cd packages/vantage
DATABASE_URL="postgres://postgres:test@localhost:55432/postgres?sslmode=disable" \
  JWT_SECRET=$(openssl rand -base64 48) \
  SECRETS_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  ADMIN_PASSWORD='DevTime!2026Pw' \
  CORS_ORIGINS=http://localhost:3001 \
  go run .

# 3. Dashboard (second shell)
cd apps/dashboard
NEXT_PUBLIC_API_URL=http://localhost:9090/api/v1 \
  pnpm dev
```

Server on `:9090`, dashboard on `:3001`. Set `CORS_ORIGINS` to the dashboard origin so browser fetch succeeds.

## Monorepo scripts

| Command | Effect |
|---------|--------|
| `pnpm install` | Install workspace deps |
| `pnpm build` | Turbo: build every package |
| `pnpm dev` | Turbo: run every dev task |
| `pnpm build:dashboard` | Just the Next.js dashboard |
| `pnpm dev:dashboard` | Dashboard dev server |
| `pnpm dev:vantage` | `go run .` in `packages/vantage` |
| `pnpm build:vantage` | `go build` Vantage binary into `bin/vantage` |
| `pnpm test:go` | `go test ./packages/...` |
| `pnpm lint` | Turbo: lint every package |

## Tech stack

- **Server**: Go 1.25 + Fiber v2 + `database/sql` + lib/pq + bcrypt + golang-jwt v5
- **Database**: PostgreSQL 16+ (no SQLite — federation needs the concurrency story)
- **Cache / pubsub**: Redis 7 (used in F2+ for cross-process coordination)
- **Frontend**: Next.js 15 (App Router) + React 19 + Tailwind 3.4 + axios
- **Reverse proxy**: Caddy 2 (auto-TLS via Let's Encrypt)
- **Auth**: stateful JWT sessions, httpOnly auth_token cookie, double-submit CSRF, bcrypt cost 12

## Related projects

- **[VaporwareRMM Edge](https://github.com/doombadroid/VaporwareRMM-Edge)** — the on-site / single-server product. Each customer site in a federated deployment runs Edge; standalone deployments (home users, self-hosters, MSPs not doing federation) run Edge alone without Vantage.

## License

[AGPL-3.0](LICENSE), same as VaporwareRMM Edge.
