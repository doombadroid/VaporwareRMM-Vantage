FROM golang:1.25-alpine AS builder

WORKDIR /app

# lib/pq is pure Go (no CGO needed). git is for the build-version
# embed in case F8 wires `git describe` into the binary.
RUN apk add --no-cache git

# Cache deps before copying source.
COPY packages/models/go.mod ./packages/models/
COPY packages/vantage/go.mod packages/vantage/go.sum ./packages/vantage/

RUN cd packages/models && go mod download
RUN cd packages/vantage && go mod download

# Copy source.
COPY packages/vantage/ ./packages/vantage/
COPY packages/models/ ./packages/models/

RUN cd packages/vantage && \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo unknown)" -o /app/vantage .

# ── Runtime ────────────────────────────────────────────────
FROM alpine:3.21

WORKDIR /app

RUN apk --no-cache add ca-certificates wget

RUN addgroup -g 1001 -S vapor && \
    adduser  -S vapor -u 1001 -G vapor

COPY --from=builder --chown=vapor:vapor /app/vantage ./vantage

EXPOSE 9090

USER vapor

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

CMD ["./vantage"]
