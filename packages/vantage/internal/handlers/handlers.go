// Package handlers wires HTTP endpoints. F1 ships /health (public),
// auth login/logout (public), /api/v1/users/me (auth), and
// /api/v1/edges (auth, returns empty paginated list).
//
// F2-F8 add /api/edge/* (federation protocol), drill-through SSO
// (F5), command routing (F4), audit checkpoint exchange (F4 wiring).
//
// Pagination shape matches Edge:
//
//	{ data, total, limit, offset, has_more }
//
// Operators consume the same response from either product.
package handlers

import (
	"database/sql"
	"errors"
	"strconv"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"

	"github.com/gofiber/fiber/v2"
)

// RegisterPublicRoutes wires endpoints that DO NOT require auth.
// /health is the canonical liveness check; auth login/logout are
// public so users can establish a session. CSRF middleware is
// NOT applied to login — the request that creates the cookie can't
// also be required to present it.
func RegisterPublicRoutes(app *fiber.App) {
	app.Get("/health", healthHandler)
	app.Post("/api/v1/auth/login", loginHandler)
	app.Post("/api/v1/auth/logout", logoutHandler)
}

// RegisterAuthedRoutes wires endpoints that require AuthMiddleware
// (already applied by the caller via app.Group). CSRFMiddleware also
// applied at the group level for state-changing methods.
func RegisterAuthedRoutes(g fiber.Router) {
	g.Get("/users/me", currentUserHandler)
	g.Get("/edges", listEdgesHandler)
	RegisterTailscaleRoutes(g)
	RegisterEnrollmentRoutes(g)
	RegisterCommandRoutes(g)
}

func healthHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}

func loginHandler(c *fiber.Ctx) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}

	var userID, hash, role string
	err := db.DB.QueryRow(`SELECT id, password_hash, role FROM users WHERE email = $1`, req.Email).
		Scan(&userID, &hash, &role)
	if errors.Is(err, sql.ErrNoRows) {
		// Don't leak whether the email exists — same response shape
		// whether the user is unknown or the password is wrong.
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "lookup failed"})
	}
	if !auth.VerifyPassword(hash, req.Password) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}

	jwtPlain, csrf, err := auth.CreateSession(userID, c.IP(), string(c.Request().Header.UserAgent()))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session creation failed"})
	}
	auth.SetSessionCookies(c, jwtPlain, csrf)

	// Update last_login_at — best-effort, login still succeeds if
	// this UPDATE fails (e.g., transient DB hiccup).
	_, _ = db.DB.Exec(`UPDATE users SET last_login_at = $1 WHERE id = $2`, time.Now(), userID)

	events.AuditLog(userID, "user.login", "user", userID,
		"login successful", c.IP())

	return c.JSON(fiber.Map{
		"user_id":    userID,
		"role":       role,
		"expires_at": time.Now().Add(24 * time.Hour).Unix(),
	})
}

func logoutHandler(c *fiber.Ctx) error {
	if tok := c.Cookies("auth_token"); tok != "" {
		// Best-effort: capture the user_id from the session before
		// revoking, so the audit row names the actor. If the
		// cookie is invalid the row reads "system" — that's fine,
		// the logout still succeeds.
		userID, _, err := auth.ValidateJWT(tok)
		if err == nil {
			events.AuditLog(userID, "user.logout", "user", userID,
				"logout", c.IP())
		}
		_ = auth.RevokeSession(tok)
	}
	auth.ClearSessionCookies(c)
	return c.JSON(fiber.Map{"message": "logged out"})
}

func currentUserHandler(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	role, _ := c.Locals("user_role").(string)
	var email string
	var lastLogin sql.NullTime
	if err := db.DB.QueryRow(
		`SELECT email, last_login_at FROM users WHERE id = $1`, userID,
	).Scan(&email, &lastLogin); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "lookup failed"})
	}
	out := fiber.Map{
		"id":    userID,
		"email": email,
		"role":  role,
	}
	if lastLogin.Valid {
		out["last_login_at"] = lastLogin.Time.Unix()
	}
	return c.JSON(out)
}

// Edge is the JSON shape returned by /api/v1/edges. F2 widens the
// schema; subsequent phases may add more (drill-through metadata,
// command queue depth, etc.) without breaking the dashboard since
// the contract only adds optional fields, not removes/renames them.
//
// token_hash is intentionally never serialized — the plaintext is
// returned exactly once at registration and the hash is for
// server-side lookup only.
type Edge struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	TenantID        string `json:"tenant_id"`
	Status          string `json:"status"`
	TailnetIP       string `json:"tailnet_ip,omitempty"`
	TailnetIdentity string `json:"tailnet_identity,omitempty"`
	EdgeVersion     string `json:"edge_version,omitempty"`
	LastSeenAt      int64  `json:"last_seen_at,omitempty"`
	TokenExpiresAt  int64  `json:"token_expires_at,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	DecommissionedAt int64 `json:"decommissioned_at,omitempty"`
	OperatorNotes   string `json:"operator_notes,omitempty"`
}

func listEdgesHandler(c *fiber.Ctx) error {
	limit, offset := parsePagination(c)

	var total int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM edges`).Scan(&total); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "count failed"})
	}

	rows, err := db.DB.Query(
		`SELECT id,
		        COALESCE(name, ''),
		        tenant_id,
		        status,
		        COALESCE(tailnet_ip, ''),
		        COALESCE(tailnet_identity, ''),
		        COALESCE(edge_version, ''),
		        COALESCE(last_seen_at, 0),
		        COALESCE(token_expires_at, 0),
		        created_at,
		        COALESCE(decommissioned_at, 0),
		        COALESCE(operator_notes, '')
		   FROM edges
		  ORDER BY created_at DESC
		  LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	out := []Edge{}
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.ID, &e.Name, &e.TenantID, &e.Status,
			&e.TailnetIP, &e.TailnetIdentity, &e.EdgeVersion,
			&e.LastSeenAt, &e.TokenExpiresAt, &e.CreatedAt,
			&e.DecommissionedAt, &e.OperatorNotes); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "scan failed"})
		}
		out = append(out, e)
	}
	return c.JSON(fiber.Map{
		"data":     out,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+len(out) < total,
	})
}

// parsePagination reads ?limit= and ?offset= with reasonable bounds.
// Limit capped at 200 so a malicious caller can't issue an
// unbounded query.
func parsePagination(c *fiber.Ctx) (int, int) {
	limit := 50
	offset := 0
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
