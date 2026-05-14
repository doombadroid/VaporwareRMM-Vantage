package main

import (
	"log/slog"
	"os"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/handlers"

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

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		AppName:               "vaporrmm-vantage",
		// Limit body sizes to a reasonable max — federation
		// payloads in F2-F8 won't exceed this; bigger bodies are
		// almost certainly malformed.
		BodyLimit: 10 * 1024 * 1024,
	})
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
