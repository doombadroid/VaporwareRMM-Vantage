package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/handlers"
	"vaporrmm/vantage/internal/signing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// version is overridable at link time via -ldflags="-X main.version=..."
// once the F8 production-readiness pass wires a release-tag build.
var version = "0.1.0-f1-skeleton"

func main() {
	slog.Info("vantage starting", "version", version)

	// Order matters: crypto first (gates on SECRETS_ENCRYPTION_KEY),
	// auth.Init second (gates on JWT_SECRET), db third (gates on
	// DATABASE_URL + runs migrations), admin bootstrap fourth.
	// Every gate refuses to proceed on a misconfiguration so an
	// operator running with half-baked env vars hits the loudest
	// possible error.
	if err := crypto.MustBeEnabled(); err != nil {
		slog.Error("crypto required at boot; refusing to start", "error", err)
		os.Exit(1)
	}
	if err := auth.Init(); err != nil {
		slog.Error("auth init failed; refusing to start", "error", err)
		os.Exit(1)
	}
	if err := db.Init(); err != nil {
		slog.Error("db init failed; refusing to start", "error", err)
		os.Exit(1)
	}
	if err := auth.BootstrapAdmin(); err != nil {
		slog.Error("admin bootstrap failed; refusing to start", "error", err)
		os.Exit(1)
	}
	if err := signing.Bootstrap(); err != nil {
		slog.Error("signing keypair bootstrap failed; refusing to start", "error", err)
		os.Exit(1)
	}
	if err := handlers.ValidateMinEdgeVersion(); err != nil {
		slog.Error("MINIMUM_REQUIRED_EDGE_VERSION invalid; refusing to start", "error", err)
		os.Exit(1)
	}

	cfg, err := buildFiberConfig(os.Getenv("TRUSTED_PROXIES"), os.Getenv("VANTAGE_PUBLIC_URL"))
	if err != nil {
		slog.Error("fiber config invalid; refusing to start", "error", err)
		os.Exit(1)
	}
	app := fiber.New(cfg)
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} ${method} ${path} ${latency}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			// Dashboard at :3001 in dev, dashboard at the same
			// origin as the API in prod (Caddy front). Allow
			// both by accepting any origin that matches an env
			// allowlist. Empty allowlist → allow none, which is
			// the production default behind Caddy.
			allow := os.Getenv("CORS_ORIGINS")
			if allow == "" {
				return false
			}
			// Simple comma-split allowlist. Keeps the surface
			// minimal until F2 needs fancier behavior.
			for _, o := range splitAndTrim(allow, ",") {
				if o == origin {
					return true
				}
			}
			return false
		},
		AllowCredentials: true,
		AllowHeaders:     "Content-Type, X-CSRF-Token",
	}))

	handlers.RegisterPublicRoutes(app)
	handlers.RegisterEdgeRoutes(app)
	api := app.Group("/api/v1", auth.AuthMiddleware(), auth.CSRFMiddleware())
	handlers.RegisterAuthedRoutes(api)

	port := "9090"
	if p := os.Getenv("VANTAGE_PORT"); p != "" {
		port = p
	}
	slog.Info("listening", "port", port)
	if err := app.Listen(":" + port); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

// buildFiberConfig assembles the fiber.Config and decides whether
// to honor X-Forwarded-For based on TRUSTED_PROXIES.
//
// Codex round-7 #1/#2 caught two bugs in the round-6 fix:
//
//   - ProxyHeader was set unconditionally. With EnableTrustedProxy
//     Check=false (no TRUSTED_PROXIES configured), Fiber still
//     read the header and trusted whatever the caller sent —
//     attackers could spoof their IP and trivially bypass per-IP
//     rate limits.
//   - EnableIPValidation was unset. Even with trust correctly
//     scoped, Fiber returned the raw header value (which can be a
//     comma-separated chain) rather than a single validated IP.
//
// New behavior: ProxyHeader is set ONLY when TRUSTED_PROXIES is
// configured. Untrusted forward headers are ignored — c.IP()
// returns the socket peer's IP, which is what untrusted callers
// can never spoof. EnableIPValidation forces Fiber to parse the
// forwarded value and reject garbage.
//
// Returns an error on invalid CIDR rather than os.Exit so tests
// can exercise the validation path.
func buildFiberConfig(trustedProxiesCSV, publicURL string) (fiber.Config, error) {
	cfg := fiber.Config{
		DisableStartupMessage: true,
		AppName:               "vaporrmm-vantage",
		// Limit body sizes to a reasonable max — federation
		// payloads in F2-F8 won't exceed this; bigger bodies are
		// almost certainly malformed.
		BodyLimit: 10 * 1024 * 1024,
	}

	trusted, err := parseTrustedProxies(trustedProxiesCSV)
	if err != nil {
		return cfg, err
	}

	if len(trusted) > 0 {
		// Operator explicitly configured trusted proxies. Honor
		// X-Forwarded-For ONLY when the immediate peer is in the
		// trusted list.
		cfg.EnableTrustedProxyCheck = true
		cfg.TrustedProxies = trusted
		cfg.ProxyHeader = fiber.HeaderXForwardedFor
		cfg.EnableIPValidation = true
		slog.Info("trusted proxy mode enabled",
			"trusted_proxies", trusted,
			"proxy_header", fiber.HeaderXForwardedFor)
	} else {
		// TRUSTED_PROXIES unset: do NOT trust any forward header.
		// c.IP() returns the socket peer — correct for direct-
		// internet deployment, wrong for behind-proxy. The
		// alternative (default ProxyHeader=X-Forwarded-For without
		// trusted-list scoping) would let attackers spoof c.IP()
		// to whatever they please.
		baseMsg := "TRUSTED_PROXIES not set; using socket peer IP for client identity. " +
			"If Vantage is behind a reverse proxy, set TRUSTED_PROXIES to the proxy's IP " +
			"range (e.g. '127.0.0.1/32,::1/128' for co-located Caddy) to enable correct " +
			"rate limiting and audit logging."
		// Stronger warning when deployment shape suggests proxy
		// fronting (https public URL).
		if strings.HasPrefix(strings.ToLower(publicURL), "https://") {
			slog.Warn("likely-misconfigured proxy: " + baseMsg)
		} else {
			slog.Warn(baseMsg)
		}
	}

	return cfg, nil
}

// parseTrustedProxies splits a CSV of CIDRs/IPs and validates each
// entry. Returns nil + nil when the input is empty (operator
// hasn't configured anything; not an error). Returns error on the
// first invalid entry so main() can surface a remediation message.
//
// Accepts both CIDRs ("127.0.0.1/32") and bare IPs ("10.0.0.5") —
// bare IPs are promoted to /32 (IPv4) or /128 (IPv6) for net.ParseCIDR.
func parseTrustedProxies(csv string) ([]string, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	parts := strings.Split(csv, ",")
	result := make([]string, 0, len(parts))
	for _, raw := range parts {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		candidate := p
		if !strings.Contains(p, "/") {
			// Promote bare IP to host CIDR for validation.
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is neither an IP nor a CIDR; expected e.g. 127.0.0.1/32 or 10.0.0.5", p)
			}
			if ip.To4() != nil {
				candidate = p + "/32"
			} else {
				candidate = p + "/128"
			}
		}
		if _, _, err := net.ParseCIDR(candidate); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not a valid CIDR: %w", p, err)
		}
		result = append(result, candidate)
	}
	return result, nil
}

func splitAndTrim(s, sep string) []string {
	out := []string{}
	current := ""
	for _, r := range s {
		if string(r) == sep {
			if current != "" {
				out = append(out, trimSpace(current))
				current = ""
			}
			continue
		}
		current += string(r)
	}
	if current != "" {
		out = append(out, trimSpace(current))
	}
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
