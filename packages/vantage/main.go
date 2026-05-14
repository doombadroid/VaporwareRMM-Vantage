package main

import (
	"log/slog"
	"os"

	"vaporrmm/vantage/internal/crypto"
)

// F1 skeleton entry point. Verifies the foundation:
//
//   - crypto package initialized at import time (refuses to boot
//     without SECRETS_ENCRYPTION_KEY in non-dev mode)
//   - main() does the explicit MustBeEnabled check so the binary
//     fails loudly even in code paths that don't directly touch
//     crypto.Encrypt
//
// F2 wires the database + auth + Fiber server. For now main is
// intentionally minimal so the build chain (go.work, go.mod,
// internal/crypto) can be verified before adding more surface.
func main() {
	slog.Info("vantage starting", "version", "0.1.0-f1-skeleton")
	if err := crypto.MustBeEnabled(); err != nil {
		slog.Error("crypto required at boot; refusing to start", "error", err)
		os.Exit(1)
	}
	slog.Info("vantage boot complete (no server loop yet — F1 scaffold)")
}
