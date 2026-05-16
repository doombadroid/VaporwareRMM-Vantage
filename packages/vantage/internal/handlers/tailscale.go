// Tailscale OAuth credential storage for Vantage (issue #22 Q3 /
// issue #18). Super-admin only — the credential can mint auth keys
// for any Edge in the fleet, so anyone with rotation/disconnect
// power has, transitively, the ability to break or take over every
// paired Edge.
//
// Mirrors Edge's Phase-1 endpoints (validate/connect/get/rotate/
// disconnect/devices) with Vantage-specific scoping:
//
//   - No tenant-admin downgrade path on GET. Vantage doesn't host
//     tenant-scoped admins for federation v1; everyone with API
//     access on Vantage is an MSP operator.
//   - Postgres-only, so the SQL uses $1/$2 placeholders directly.
//   - Audit log uses events.AuditLog (no tenant_id parameter).

package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"
	"vaporrmm/vantage/internal/tailscale"

	"github.com/gofiber/fiber/v2"
)

// tailscaleClientFactory lets tests inject a fake. Production
// returns the real wrapper.
var tailscaleClientFactory = func(clientID, clientSecret string) tailscaleAPI {
	return tailscale.NewClient(clientID, clientSecret)
}

// tailscaleAPI is the subset of *tailscale.Client the handler uses.
// Extracted so tests can substitute a fake without spinning up an
// httptest.Server per case.
type tailscaleAPI interface {
	Authenticate(ctx context.Context) error
	ListTailnets(ctx context.Context) ([]tailscale.Tailnet, error)
	ValidateAuthKeyScope(ctx context.Context, tailnet string) error
	ValidateDeviceListScope(ctx context.Context, tailnet string) error
	ListDevices(ctx context.Context, tailnet string) ([]tailscale.Device, error)
	MintEdgeEnrollmentAuthKey(ctx context.Context, tailnet, description string) (*tailscale.AuthKey, error)
	RevokeAuthKey(ctx context.Context, tailnet, keyID string) error
}

// RegisterTailscaleRoutes wires the Phase-1 endpoints under the
// caller's group (callers attach to /api/v1). Every handler asserts
// super-admin via requireSuperAdmin.
func RegisterTailscaleRoutes(api fiber.Router) {
	api.Post("/tailscale/validate", requireSuperAdmin, validateTailscaleCredential)
	api.Post("/tailscale/connect", requireSuperAdmin, connectTailscale)
	api.Get("/tailscale/connection", requireSuperAdmin, getTailscaleConnection)
	api.Put("/tailscale/connection", requireSuperAdmin, rotateTailscaleConnection)
	api.Delete("/tailscale/connection", requireSuperAdmin, disconnectTailscale)
	api.Get("/tailscale/devices", requireSuperAdmin, listTailscaleDevices)
}

func requireSuperAdmin(c *fiber.Ctx) error {
	role, _ := c.Locals("user_role").(string)
	if !auth.IsSuperAdmin(role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Tailscale management requires super-admin",
			"code":  403,
		})
	}
	return c.Next()
}

func validateTailscaleCredential(c *fiber.Ctx) error {
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Tailnet      string `json:"tailnet,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
	}
	if req.ClientID == "" || req.ClientSecret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "client_id and client_secret are required"})
	}

	cl := tailscaleClientFactory(req.ClientID, req.ClientSecret)
	ctx := c.UserContext()
	checks := map[string]string{
		"authentication":    "pending",
		"auth_key_scope":    "pending",
		"device_list_scope": "pending",
	}
	errorsMap := map[string]string{}
	tailnets := []tailscale.Tailnet{}

	if err := cl.Authenticate(ctx); err != nil {
		checks["authentication"] = "failed"
		errorsMap["authentication"] = classifyTailscaleError(err,
			"Verify the OAuth client_id / client_secret at https://login.tailscale.com/admin/settings/oauth")
		return c.JSON(fiber.Map{"checks": checks, "errors": errorsMap, "tailnets": tailnets})
	}
	checks["authentication"] = "ok"

	if req.Tailnet == "" {
		tn, err := cl.ListTailnets(ctx)
		if err != nil {
			errorsMap["tailnets"] = classifyTailscaleError(err,
				"Could not enumerate tailnets — confirm the OAuth client is bound to a tailnet")
			return c.JSON(fiber.Map{"checks": checks, "errors": errorsMap, "tailnets": tailnets})
		}
		tailnets = tn
		if len(tn) == 1 {
			req.Tailnet = tn[0].Name
		}
	}
	if req.Tailnet == "" {
		return c.JSON(fiber.Map{"checks": checks, "errors": errorsMap, "tailnets": tailnets})
	}

	if err := cl.ValidateAuthKeyScope(ctx, req.Tailnet); err != nil {
		checks["auth_key_scope"] = "failed"
		errorsMap["auth_key_scope"] = classifyTailscaleError(err,
			"Grant the OAuth client the 'auth_keys' (write) scope at https://login.tailscale.com/admin/settings/oauth")
	} else {
		checks["auth_key_scope"] = "ok"
	}

	if err := cl.ValidateDeviceListScope(ctx, req.Tailnet); err != nil {
		checks["device_list_scope"] = "failed"
		errorsMap["device_list_scope"] = classifyTailscaleError(err,
			"Grant the OAuth client the 'devices' (read) scope at https://login.tailscale.com/admin/settings/oauth")
	} else {
		checks["device_list_scope"] = "ok"
	}

	if len(tailnets) == 0 {
		tailnets = []tailscale.Tailnet{{Name: req.Tailnet}}
	}
	return c.JSON(fiber.Map{
		"checks":   checks,
		"errors":   errorsMap,
		"tailnets": tailnets,
	})
}

func connectTailscale(c *fiber.Ctx) error {
	if err := crypto.MustBeEnabled(); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Encryption is required to store Tailscale credentials. Set SECRETS_ENCRYPTION_KEY.",
		})
	}
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Tailnet      string `json:"tailnet"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
	}
	if req.ClientID == "" || req.ClientSecret == "" || req.Tailnet == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "client_id, client_secret, and tailnet are required"})
	}

	if err := runValidationChecks(c.UserContext(), req.ClientID, req.ClientSecret, req.Tailnet); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	encID, err := crypto.Encrypt(req.ClientID)
	if err != nil {
		slog.Error("tailscale: encrypt client_id", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt credential"})
	}
	encSecret, err := crypto.Encrypt(req.ClientSecret)
	if err != nil {
		slog.Error("tailscale: encrypt client_secret", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt credential"})
	}

	// Atomic singleton insert (codex round-3 finding #4). The pre-
	// fix SELECT-then-INSERT pattern raced concurrent connects;
	// the loser hit the PK constraint and returned 500. ON
	// CONFLICT DO NOTHING + RowsAffected check gives a
	// deterministic 409 for the loser.
	now := time.Now().Unix()
	userID, _ := c.Locals("user_id").(string)
	result, err := db.DB.Exec(
		`INSERT INTO tailscale_connection (id, oauth_client_id_encrypted, oauth_client_secret_encrypted, tailnet, tailnet_display_name, connected_at, connected_by_user_id, last_validated_at)
		     VALUES ('singleton', $1, $2, $3, $4, $5, $6, $7)
		     ON CONFLICT (id) DO NOTHING`,
		encID, encSecret, req.Tailnet, "", now, userID, now,
	)
	if err != nil {
		slog.Error("tailscale: persist", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to persist connection"})
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("tailscale: rowsAffected", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to verify connection persisted"})
	}
	if rowsAffected == 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Tailscale already connected; use PUT /api/v1/tailscale/connection to rotate, or DELETE first.",
			"code":  "already_connected",
		})
	}

	events.AuditLog(userID, "tailscale.connected", "tailscale_connection", "singleton",
		fmt.Sprintf("connected to tailnet %s", req.Tailnet), c.IP())

	return c.JSON(fiber.Map{
		"tailnet":      req.Tailnet,
		"connected_at": now,
	})
}

func getTailscaleConnection(c *fiber.Ctx) error {
	var tailnet, displayName, connectedBy string
	var connectedAt, lastValidated, rotated sql.NullInt64
	var lastValidationError sql.NullString
	err := db.DB.QueryRow(
		`SELECT tailnet, COALESCE(tailnet_display_name, ''), connected_at, COALESCE(connected_by_user_id, ''), last_validated_at, last_validation_error, rotated_at FROM tailscale_connection WHERE id = 'singleton'`,
	).Scan(&tailnet, &displayName, &connectedAt, &connectedBy, &lastValidated, &lastValidationError, &rotated)
	if errors.Is(err, sql.ErrNoRows) {
		return c.JSON(fiber.Map{"connected": false})
	}
	if err != nil {
		slog.Warn("tailscale: get connection", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read connection"})
	}

	display := displayName
	if display == "" {
		display = tailnet
	}
	out := fiber.Map{
		"connected":            true,
		"tailnet":              tailnet,
		"tailnet_display_name": display,
		"connected_at":         connectedAt.Int64,
		"connected_by_user_id": connectedBy,
	}
	if lastValidated.Valid {
		out["last_validated_at"] = lastValidated.Int64
	}
	if lastValidationError.Valid && lastValidationError.String != "" {
		out["last_validation_error"] = lastValidationError.String
	}
	if rotated.Valid {
		out["rotated_at"] = rotated.Int64
	}
	return c.JSON(out)
}

func rotateTailscaleConnection(c *fiber.Ctx) error {
	if err := crypto.MustBeEnabled(); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Encryption is required to store Tailscale credentials.",
		})
	}
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
	}
	if req.ClientID == "" || req.ClientSecret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "client_id and client_secret are required"})
	}

	var existingTailnet string
	if err := db.DB.QueryRow(`SELECT tailnet FROM tailscale_connection WHERE id = 'singleton'`).Scan(&existingTailnet); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Tailscale not currently connected; use POST /api/v1/tailscale/connect to establish credentials.",
				"code":  "not_connected",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read existing connection"})
	}

	cl := tailscaleClientFactory(req.ClientID, req.ClientSecret)
	ctx := c.UserContext()
	if err := cl.Authenticate(ctx); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": classifyTailscaleError(err, "Rotation refused: new credential failed authentication"),
		})
	}
	tns, err := cl.ListTailnets(ctx)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": classifyTailscaleError(err, "Rotation refused: could not enumerate new credential's tailnets"),
		})
	}
	matchedTailnet := ""
	for _, t := range tns {
		if t.Name == existingTailnet {
			matchedTailnet = t.Name
			break
		}
	}
	if matchedTailnet == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Rotation refused: new credential owns tailnet(s) %s but existing connection is on tailnet %s. Disconnect and reconnect to change tailnets, which will require re-onboarding all Edges.",
				tailnetsList(tns), existingTailnet),
		})
	}
	if err := cl.ValidateAuthKeyScope(ctx, matchedTailnet); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": classifyTailscaleError(err, "auth_keys scope missing on new credential")})
	}
	if err := cl.ValidateDeviceListScope(ctx, matchedTailnet); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": classifyTailscaleError(err, "devices scope missing on new credential")})
	}

	encID, err := crypto.Encrypt(req.ClientID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt new credential"})
	}
	encSecret, err := crypto.Encrypt(req.ClientSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt new credential"})
	}

	// Compare-and-set on tailnet (codex round-6 #4). The existing
	// tailnet was read into existingTailnet earlier in this
	// handler; include it as a WHERE predicate so a concurrent
	// disconnect+reconnect to a DIFFERENT tailnet can't have us
	// rotating credentials onto a row whose semantics changed
	// since our pre-check. Distinguish "no singleton" from
	// "singleton has different tailnet now" via a follow-up SELECT.
	now := time.Now().Unix()
	result, err := db.DB.Exec(
		`UPDATE tailscale_connection
		     SET oauth_client_id_encrypted = $1, oauth_client_secret_encrypted = $2, rotated_at = $3, last_validated_at = $4, last_validation_error = NULL
		     WHERE id = 'singleton' AND tailnet = $5`,
		encID, encSecret, now, now, existingTailnet,
	)
	if err != nil {
		slog.Error("tailscale: rotate UPDATE", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to swap credential"})
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("tailscale: rotate rowsAffected", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to verify rotation"})
	}
	if rowsAffected == 0 {
		var currentTailnet sql.NullString
		diagErr := db.DB.QueryRow(`SELECT tailnet FROM tailscale_connection WHERE id = 'singleton'`).Scan(&currentTailnet)
		if errors.Is(diagErr, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Tailscale not currently connected; use POST /api/v1/tailscale/connect to establish credentials.",
				"code":  "not_connected",
			})
		}
		if diagErr != nil {
			slog.Error("tailscale: rotate diagnose", "error", diagErr)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rotate diagnose failed"})
		}
		// Singleton still exists but tailnet drifted.
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":           "Tailscale connection changed concurrently; refresh and retry rotation",
			"code":            "tailnet_changed_concurrently",
			"current_tailnet": currentTailnet.String,
		})
	}

	userID, _ := c.Locals("user_id").(string)
	events.AuditLog(userID, "tailscale.rotated", "tailscale_connection", "singleton",
		fmt.Sprintf("rotated credential for tailnet %s", existingTailnet), c.IP())

	return c.JSON(fiber.Map{"rotated_at": now, "tailnet": existingTailnet})
}

func disconnectTailscale(c *fiber.Ctx) error {
	var existingTailnet string
	if err := db.DB.QueryRow(`SELECT tailnet FROM tailscale_connection WHERE id = 'singleton'`).Scan(&existingTailnet); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(fiber.Map{"disconnected": true})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read connection"})
	}
	// Compare-and-set on tailnet (codex round-10 #2): without it,
	// a concurrent rotate that flipped the tailnet between our
	// SELECT and DELETE would still delete the row, and the
	// audit row below would report the OLD tailnet name. The
	// CAS predicate refuses the delete if the row drifted.
	result, err := db.DB.Exec(
		`DELETE FROM tailscale_connection WHERE id = 'singleton' AND tailnet = $1`,
		existingTailnet,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete connection"})
	}
	rowsAffected, raErr := result.RowsAffected()
	if raErr != nil {
		slog.Error("tailscale: disconnect rowsAffected", "error", raErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to verify disconnect"})
	}
	if rowsAffected == 0 {
		// Singleton drifted (concurrent rotate to a different
		// tailnet) or was already deleted. Either way, the
		// disconnect didn't act on what we read — surface 409 so
		// the operator can refresh and reconsider.
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Tailscale connection changed concurrently; refresh and retry disconnect",
			"code":  "tailnet_changed_concurrently",
		})
	}
	userID, _ := c.Locals("user_id").(string)
	events.AuditLog(userID, "tailscale.disconnected", "tailscale_connection", "singleton",
		fmt.Sprintf("disconnected from tailnet %s", existingTailnet), c.IP())
	return c.JSON(fiber.Map{"disconnected": true})
}

func listTailscaleDevices(c *fiber.Ctx) error {
	clientID, clientSecret, tailnet, ok, err := loadTailscaleCredential()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Not connected to Tailscale"})
	}
	cl := tailscaleClientFactory(clientID, clientSecret)
	devs, err := cl.ListDevices(c.UserContext(), tailnet)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": classifyTailscaleError(err, "Failed to list devices from Tailscale"),
		})
	}
	return c.JSON(fiber.Map{"devices": devs, "tailnet": tailnet})
}

// loadTailscaleCredential reads + decrypts the stored credential.
// Returns ok=false if no connection exists. Used by the enrollment-
// token handler (commit 6) to mint per-Edge auth keys.
func loadTailscaleCredential() (clientID, clientSecret, tailnet string, ok bool, err error) {
	var encID, encSecret, tn string
	scanErr := db.DB.QueryRow(
		`SELECT oauth_client_id_encrypted, oauth_client_secret_encrypted, tailnet FROM tailscale_connection WHERE id = 'singleton'`,
	).Scan(&encID, &encSecret, &tn)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if scanErr != nil {
		return "", "", "", false, fmt.Errorf("read tailscale connection: %w", scanErr)
	}
	clientID, err = crypto.Decrypt(encID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("decrypt client_id: %w", err)
	}
	clientSecret, err = crypto.Decrypt(encSecret)
	if err != nil {
		return "", "", "", false, fmt.Errorf("decrypt client_secret: %w", err)
	}
	return clientID, clientSecret, tn, true, nil
}

func runValidationChecks(ctx context.Context, clientID, clientSecret, tailnet string) error {
	cl := tailscaleClientFactory(clientID, clientSecret)
	if err := cl.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication: %s", classifyTailscaleError(err, ""))
	}
	if err := cl.ValidateAuthKeyScope(ctx, tailnet); err != nil {
		return fmt.Errorf("auth_keys scope: %s", classifyTailscaleError(err, ""))
	}
	if err := cl.ValidateDeviceListScope(ctx, tailnet); err != nil {
		return fmt.Errorf("devices scope: %s", classifyTailscaleError(err, ""))
	}
	return nil
}

func classifyTailscaleError(err error, fallback string) string {
	switch {
	case errors.Is(err, tailscale.ErrTailscaleUnreachable):
		return "Tailscale control plane unreachable. Check connectivity and retry."
	case errors.Is(err, tailscale.ErrTailscaleAuthFailed):
		return "Authentication failed. Verify the OAuth client_id / client_secret at https://login.tailscale.com/admin/settings/oauth"
	case errors.Is(err, tailscale.ErrTailscaleScopeMissingAuthKeys):
		return "OAuth client missing the 'auth_keys' (write) scope. Edit it at https://login.tailscale.com/admin/settings/oauth"
	case errors.Is(err, tailscale.ErrTailscaleScopeMissingDeviceList):
		return "OAuth client missing the 'devices' (read) scope. Edit it at https://login.tailscale.com/admin/settings/oauth"
	case errors.Is(err, tailscale.ErrTailscaleRateLimited):
		var rl *tailscale.RateLimitedError
		if errors.As(err, &rl) {
			return fmt.Sprintf("Tailscale rate limit hit. Retry after %d seconds.", rl.RetryAfterSeconds)
		}
		return "Tailscale rate limit hit. Retry shortly."
	}
	if fallback != "" {
		return fallback + ": " + err.Error()
	}
	return err.Error()
}

func tailnetsList(tns []tailscale.Tailnet) string {
	names := make([]string, 0, len(tns))
	for _, t := range tns {
		names = append(names, t.Name)
	}
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += url.PathEscape(n)
	}
	return out
}
