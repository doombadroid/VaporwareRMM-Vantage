FROM node:22-alpine AS builder

WORKDIR /app

# NEXT_PUBLIC_API_URL is baked into the JS bundle at build time.
# Behind Caddy in compose: /api/v1. Standalone Vantage: rewrite
# at build to http://<host>:9090/api/v1 if the dashboard is on a
# different origin from Vantage.
ARG NEXT_PUBLIC_API_URL=/api/v1
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

# Workspace manifests for dep caching.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json turbo.json ./
COPY apps/dashboard/package.json ./apps/dashboard/

RUN corepack enable pnpm && pnpm install --frozen-lockfile

# Full dashboard source + build.
COPY apps/dashboard/ ./apps/dashboard/
RUN pnpm --filter @vaporrmm-vantage/dashboard build

# ── Runtime ────────────────────────────────────────────────
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001
ENV HOSTNAME=0.0.0.0

# wget for HEALTHCHECK. Mirrors Edge — busybox builtins are
# inconsistent in alpine releases and node -e quoting silently
# regressed twice in Edge's history. The ~1 MiB image cost beats
# the debugging time.
RUN apk add --no-cache wget

RUN addgroup -g 1001 -S nodejs && \
    adduser  -S nextjs -u 1001 -G nodejs

COPY --from=builder --chown=nextjs:nodejs /app/apps/dashboard/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/dashboard/.next/static      ./apps/dashboard/.next/static
COPY --from=builder --chown=nextjs:nodejs /app/apps/dashboard/public             ./apps/dashboard/public

EXPOSE 3001

USER nextjs

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=8 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3001/ || exit 1

CMD ["node", "apps/dashboard/server.js"]
