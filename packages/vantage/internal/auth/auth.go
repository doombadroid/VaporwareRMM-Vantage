// Package auth is Vantage's authentication and session layer. Mirror
// of Edge's pattern, scoped down to what F1 needs: JWT signed with
// HMAC-SHA256, stateful sessions backed by the user_sessions table,
// cookie-only transport (auth_token httpOnly), CSRF via double-submit
// (csrf_token cookie + X-CSRF-Token header), bcrypt password hashing
// at cost 12.
//
// Edge's auth additionally handles OIDC, TOTP, impersonation, portal
// users. Vantage doesn't need those for F1 — operators log in with
// email + password, get a session cookie, that's it. Federation
// drill-through SSO is a Phase F5 concern (separate JWT signed for
// inter-product handoff), not bundled into this package.
//
// Multi-node note: this package holds NO state in-process. JWT
// validation reads user_sessions; session creation writes there;
// nothing is cached. A horizontally-scaled Vantage works correctly
// because every node sees the same Postgres state.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// JWTSecret is the HMAC-SHA256 signing key. Loaded from JWT_SECRET
// at startup. The Init() function gates startup; main calls it
// before any handler can run.
var JWTSecret []byte

const (
	// jwtTTL is the lifetime of an issued session JWT. Stateful
	// sessions can be revoked server-side (delete the user_sessions
	// row), so the JWT TTL is generous — operators don't want to
	// re-login every shift.
	jwtTTL = 24 * time.Hour

	// bcryptCost is the cost factor for password hashing. 12 is
	// the default that lands in ~150ms per hash on modern x86
	// hardware. Higher costs slow login but raise the bar against
	// offline cracking if the password_hash column ever leaks.
	bcryptCost = 12

	// authCookie / csrfCookie are the cookie names. auth_token is
	// httpOnly (browser-side JavaScript cannot read it); csrf_token
	// is JS-readable so the dashboard can echo it back in the
	// X-CSRF-Token header on state-changing requests.
	authCookie = "auth_token"
	csrfCookie = "csrf_token"

	// csrfHeader is the header name the dashboard sends on
	// POST/PUT/DELETE/PATCH. Must match the csrf_token cookie value.
	csrfHeader = "X-CSRF-Token"
)

// Init loads JWT_SECRET and validates it. Refuses to proceed if the
// secret is absent or shorter than 32 characters — HS256 over a
// short secret is brute-forceable, which would put session forgery
// on tap.
func Init() error {
	sec := os.Getenv("JWT_SECRET")
	if sec == "" {
		return errors.New(
			"JWT_SECRET is required. Generate one with: openssl rand -base64 48",
		)
	}
	if len(sec) < 32 {
		return errors.New(
			"JWT_SECRET must be at least 32 characters (HS256 over a short secret is forgeable)",
		)
	}
	JWTSecret = []byte(sec)

	// VANTAGE_PUBLIC_URL validation (codex round-5 #3). Required
	// non-empty + parseable + scheme/host present. The handler-time
	// uses ("vantage_url" in the enrollment bundle, cookie-secure
	// cross-check) expect a valid URL, so we refuse to boot rather
	// than ship malformed values into operator-facing artifacts.
	publicURL := os.Getenv("VANTAGE_PUBLIC_URL")
	if publicURL == "" {
		return errors.New(
			"VANTAGE_PUBLIC_URL is required. Set to the tailnet-routable URL Edges will reach Vantage at, e.g. https://vantage.yourtailnet.ts.net",
		)
	}
	parsed, err := neturl.Parse(publicURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		errStr := ""
		if err != nil {
			errStr = ": " + err.Error()
		}
		return fmt.Errorf(
			"VANTAGE_PUBLIC_URL=%q is not a valid URL (need scheme and host, e.g. https://vantage.yourtailnet.ts.net)%s",
			publicURL, errStr,
		)
	}
	secureCookies := os.Getenv("FORCE_SECURE_COOKIES") != "false"
	scheme := strings.ToLower(parsed.Scheme)
	if secureCookies && scheme != "https" {
		return fmt.Errorf(
			"VANTAGE_PUBLIC_URL=%q must use https in production. Use http only with FORCE_SECURE_COOKIES=false (local dev).",
			publicURL,
		)
	}
	if !secureCookies && scheme == "https" {
		return errors.New(
			"refusing to boot: FORCE_SECURE_COOKIES=false but VANTAGE_PUBLIC_URL is https — " +
				"the combination would issue non-Secure auth cookies to a TLS deployment. " +
				"Unset FORCE_SECURE_COOKIES (defaults to true) for production, or set VANTAGE_PUBLIC_URL " +
				"to an http:// URL if this really is local development",
		)
	}
	return nil
}

// HashToken returns the hex SHA-256 of a token. Used as the
// user_sessions primary key so a database leak doesn't hand the
// attacker live session cookies.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// GenerateRandomToken returns a fresh URL-safe random token. Used
// for the CSRF cookie value.
func GenerateRandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashPassword bcrypt-hashes a plaintext password at cost 12.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword compares a candidate plaintext against a stored
// bcrypt hash. Constant-time inside bcrypt's CompareHashAndPassword.
func VerifyPassword(stored, candidate string) bool {
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil
}

// ValidatePasswordStrength enforces the complexity rules. Same shape
// as Edge: minimum 12 chars, requires uppercase, lowercase, digit,
// special. Operators who paste a too-short password during admin
// bootstrap or password change get a precise error.
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return errors.New("password must contain an uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain a lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain a digit")
	}
	if !hasSpecial {
		return errors.New("password must contain a special character")
	}
	return nil
}

// GenerateJWT issues a session token for the given user. Caller
// inserts the hash into user_sessions before returning the plaintext
// to the client — JWT validity alone is not enough; the row must
// exist (stateful sessions).
func GenerateJWT(userID, role string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"exp":  now.Add(jwtTTL).Unix(),
		"iat":  now.Unix(),
		"iss":  "vaporrmm-vantage",
		"jti":  uuid.New().String(),
	})
	return token.SignedString(JWTSecret)
}

// ValidateJWT parses and verifies an HS256 JWT signed by this server.
// Does NOT check the user_sessions table — AuthMiddleware does that
// after this returns. Returns (userID, role, error).
func ValidateJWT(s string) (string, string, error) {
	tok, err := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return JWTSecret, nil
	})
	if err != nil {
		return "", "", fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return "", "", errors.New("invalid claims")
	}
	if iss, _ := claims["iss"].(string); iss != "vaporrmm-vantage" {
		return "", "", errors.New("issuer mismatch")
	}
	userID, _ := claims["sub"].(string)
	role, _ := claims["role"].(string)
	if userID == "" {
		return "", "", errors.New("token missing subject")
	}
	return userID, role, nil
}

// CreateSession inserts a user_sessions row for the given JWT.
// Returns the JWT plaintext so the handler can set the cookie.
func CreateSession(userID, ip, userAgent string) (string, string, error) {
	var role string
	if err := db.DB.QueryRow(`SELECT role FROM users WHERE id = $1`, userID).Scan(&role); err != nil {
		return "", "", fmt.Errorf("look up user role: %w", err)
	}
	jwtPlain, err := GenerateJWT(userID, role)
	if err != nil {
		return "", "", err
	}
	csrf := GenerateRandomToken()
	if _, err := db.DB.Exec(
		`INSERT INTO user_sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5)`,
		HashToken(jwtPlain), userID, time.Now().Add(jwtTTL), ip, userAgent,
	); err != nil {
		return "", "", fmt.Errorf("insert session: %w", err)
	}
	return jwtPlain, csrf, nil
}

// RevokeSession deletes the user_sessions row for a JWT. Called by
// the logout handler so the JWT becomes invalid immediately,
// independent of its exp claim.
func RevokeSession(jwtPlain string) error {
	_, err := db.DB.Exec(`DELETE FROM user_sessions WHERE token_hash = $1`, HashToken(jwtPlain))
	return err
}

// AuthMiddleware loads the JWT from the auth_token cookie, validates
// it, confirms a user_sessions row exists, and attaches user_id +
// role to the request context. Refuses with 401 on any failure.
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tok := c.Cookies(authCookie)
		if tok == "" {
			return unauthorized(c, "missing session cookie")
		}
		userID, role, err := ValidateJWT(tok)
		if err != nil {
			return unauthorized(c, "invalid token")
		}
		var sessionUserID string
		var expiresAt time.Time
		if err := db.DB.QueryRow(
			`SELECT user_id, expires_at FROM user_sessions WHERE token_hash = $1`,
			HashToken(tok),
		).Scan(&sessionUserID, &expiresAt); err != nil {
			return unauthorized(c, "session not found")
		}
		if sessionUserID != userID {
			return unauthorized(c, "session/user mismatch")
		}
		if time.Now().After(expiresAt) {
			// Stale row — clean up so SELECTs stay fast.
			_, _ = db.DB.Exec(`DELETE FROM user_sessions WHERE token_hash = $1`, HashToken(tok))
			return unauthorized(c, "session expired")
		}
		c.Locals("user_id", userID)
		c.Locals("user_role", role)
		return c.Next()
	}
}

// CSRFMiddleware enforces the double-submit cookie pattern on
// state-changing methods. The dashboard reads csrf_token from
// document.cookie (it's NOT httpOnly) and echoes the value via
// X-CSRF-Token. Constant-time compare in subtle.ConstantTimeCompare.
func CSRFMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		m := c.Method()
		if m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions {
			return c.Next()
		}
		cookieVal := c.Cookies(csrfCookie)
		headerVal := c.Get(csrfHeader)
		if cookieVal == "" || headerVal == "" {
			return forbidden(c, "csrf token required on state-changing request")
		}
		if subtle.ConstantTimeCompare([]byte(cookieVal), []byte(headerVal)) != 1 {
			return forbidden(c, "csrf token mismatch")
		}
		return c.Next()
	}
}

// cookieSecure decides whether the Set-Cookie response carries
// the Secure flag.
//
// The original implementation derived the flag from c.Protocol()
// ("https"). Codex review on PR #1 flagged the bug: when Vantage
// runs behind a TLS-terminating proxy (Caddy in our standard
// deployment), the backend connection is plain HTTP — c.Protocol()
// returns "http", Secure is unset, and browsers will send the
// auth cookie over plain HTTP to any same-origin URL.
//
// New rule: cookies are always Secure unless the operator
// explicitly opts out via FORCE_SECURE_COOKIES=false. Default
// secure means a misconfigured dev environment fails noisy
// (cookie won't stick over http://localhost without the opt-out)
// rather than a misconfigured production environment failing
// silent (cookies fly cleartext).
//
// The startup sanity check in main.go refuses to boot when
// PUBLIC_URL is https and FORCE_SECURE_COOKIES is false — that
// combination is almost always an operator mistake.
func cookieSecure() bool {
	return os.Getenv("FORCE_SECURE_COOKIES") != "false"
}

// SetSessionCookies writes the auth_token (httpOnly) and csrf_token
// (JS-readable) cookies on a successful login.
func SetSessionCookies(c *fiber.Ctx, jwtPlain, csrfVal string) {
	secure := cookieSecure()
	c.Cookie(&fiber.Cookie{
		Name:     authCookie,
		Value:    jwtPlain,
		HTTPOnly: true,
		Secure:   secure,
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   int(jwtTTL.Seconds()),
	})
	c.Cookie(&fiber.Cookie{
		Name:     csrfCookie,
		Value:    csrfVal,
		HTTPOnly: false, // dashboard reads this to echo back
		Secure:   secure,
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   int(jwtTTL.Seconds()),
	})
}

// ClearSessionCookies wipes both cookies on logout.
func ClearSessionCookies(c *fiber.Ctx) {
	secure := cookieSecure()
	for _, name := range []string{authCookie, csrfCookie} {
		c.Cookie(&fiber.Cookie{
			Name:     name,
			Value:    "",
			HTTPOnly: name == authCookie,
			Secure:   secure,
			SameSite: "Strict",
			Path:     "/",
			MaxAge:   -1,
		})
	}
}

// IsSuperAdmin: convenience predicate. Federation will introduce
// finer roles in F2-F8; F1 keeps the two-role model from Edge.
func IsSuperAdmin(role string) bool { return role == "super_admin" }

// EdgeAuthMiddleware validates federation Bearer tokens for the
// /api/edge/poll and /api/edge/events endpoints.
//
// Per the design lock in #22 Q2, this layer was originally going
// to include a defense-in-depth check binding the Edge token to
// the source tailnet_ip recorded at registration. Codex review on
// PR #1 surfaced (correctly) that application-layer access to the
// real tailnet source IP is not reliable: when Vantage runs behind
// a reverse proxy (Caddy in production), c.IP() resolves to the
// proxy or to whatever X-Forwarded-For carries, not the original
// tailnet IP. Even direct-attached, the IP isn't a strong identity
// binding — addresses can change, be spoofed in some topologies,
// etc.
//
// The IP check was removed in F2 review (commit history). The
// active defense surface in F2 is:
//
//   - Tailscale network identity: only tailnet members can reach
//     Vantage's tailnet endpoint at all (network-layer ACL).
//
//   - Per-Edge Bearer token: SHA-256 hashed at rest, 30-day TTL
//     with poll-time rotation, application-layer cryptographic
//     identity per Edge.
//
// Future hardening (out of scope for F2): mTLS using Tailscale-
// issued node certificates, or a Tailscale-aware sidecar that
// surfaces verified peer identity into a request header Vantage
// can trust. Track follow-up against #22.
//
// Q10 still applies: no in-memory cache. Every request hits
// Postgres for the token-hash lookup. Redis cache with PUB/SUB
// invalidation is the optimization path if poll throughput at
// scale requires it.
func EdgeAuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// RFC 7235 §2.1: auth-scheme names are case-insensitive.
		// Clients in the wild send "Bearer", "bearer", and
		// occasionally "BEARER"; codex finding #4 caught that the
		// strict HasPrefix("Bearer ") check rejected everything
		// but Title case.
		const scheme = "bearer "
		authHeader := strings.TrimSpace(c.Get("Authorization"))
		if len(authHeader) < len(scheme) || !strings.EqualFold(authHeader[:len(scheme)], scheme) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing or malformed Authorization header",
				"code":  401,
			})
		}
		token := strings.TrimSpace(authHeader[len(scheme):])
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "empty bearer token", "code": 401})
		}

		tokenHash := HashToken(token)

		var (
			edgeID          string
			tenantID        string
			tailnetIdentity sql.NullString
			tokenExpiresAt  sql.NullInt64
		)
		err := db.DB.QueryRow(
			`SELECT id, tenant_id, tailnet_identity, token_expires_at
			   FROM edges
			   WHERE token_hash = $1 AND status = 'active'`,
			tokenHash,
		).Scan(&edgeID, &tenantID, &tailnetIdentity, &tokenExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unknown or inactive edge token", "code": 401})
		}
		if err != nil {
			slog.Error("edge auth: lookup", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "auth lookup failed"})
		}

		// Boundary semantics: a token whose token_expires_at lands
		// on exactly the current second is expired. The pre-fix `<`
		// comparison routed exactly-at-expiry tokens to the
		// downstream "unreachable" 500 path. <= treats the boundary
		// as expired consistently.
		if tokenExpiresAt.Valid && tokenExpiresAt.Int64 <= time.Now().Unix() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "edge token expired", "code": 401})
		}

		// Heartbeat. Update last_seen_at on every successful auth.
		// The poll handler doesn't repeat this — middleware-level
		// gives every authenticated request the same freshness.
		if _, err := db.DB.Exec(
			`UPDATE edges SET last_seen_at = $1 WHERE id = $2`,
			time.Now().Unix(), edgeID,
		); err != nil {
			slog.Warn("edge auth: last_seen_at update failed", "error", err, "edge_id", edgeID)
		}

		c.Locals("edge_id", edgeID)
		c.Locals("tenant_id", tenantID)
		c.Locals("tailnet_identity", tailnetIdentity.String)
		return c.Next()
	}
}

// BootstrapAdmin runs at startup. Creates the first admin user if
// none exist, picking up the password from ADMIN_PASSWORD or
// generating one and printing it once.
//
// The sentinel "__GENERATE_ME__" refusal mirrors Edge's
// RefuseSentinelSecrets pattern: an operator who copy-pastes
// .env.example without filling values gets an immediate, loud
// failure rather than a silently-default account.
func BootstrapAdmin() error {
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return nil // already bootstrapped
	}

	pw := os.Getenv("ADMIN_PASSWORD")
	if pw == "__GENERATE_ME__" {
		return errors.New(
			"ADMIN_PASSWORD is the sentinel '__GENERATE_ME__'. Set it to a real password or unset it (Vantage will generate one and print it once).",
		)
	}
	generated := false
	if pw == "" {
		// Generate a strong random password matching the
		// complexity rules. Mix three classes + one symbol so the
		// resulting string always passes ValidatePasswordStrength.
		rb := make([]byte, 18)
		_, _ = rand.Read(rb)
		pw = "Va!" + base64.RawURLEncoding.EncodeToString(rb)
		generated = true
	}
	if err := ValidatePasswordStrength(pw); err != nil {
		return fmt.Errorf("ADMIN_PASSWORD does not satisfy complexity rules: %w", err)
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	id := uuid.New().String()
	// ON CONFLICT (email): codex round-6 sweep caught a multi-
	// process boot race where two nodes both observe count=0 and
	// both INSERT. The second-runner would have crashed on the
	// email UNIQUE constraint. ON CONFLICT DO NOTHING lets the
	// race-loser silently no-op; admin exists either way.
	result, err := db.DB.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, 'super_admin') ON CONFLICT (email) DO NOTHING`,
		id, "admin@vaporrmm-vantage.local", hash,
	)
	if err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		// Race-lost: another booting node already created the
		// admin. Don't print "FIRST-RUN ADMIN PASSWORD" — the
		// winner already did.
		slog.Info("admin bootstrap: row already existed (race-lost on concurrent boot); no first-run banner emitted")
		return nil
	}
	if generated {
		// Print to stdout (not slog) so it doesn't get tangled in
		// JSON-structured logs; operators copy this from the
		// terminal once and store it in their password manager.
		fmt.Println("=====================================================================")
		fmt.Println("FIRST-RUN ADMIN PASSWORD (save this NOW — it is not printed again):")
		fmt.Println()
		fmt.Println("  Email:    admin@vaporrmm-vantage.local")
		fmt.Println("  Password:", pw)
		fmt.Println()
		fmt.Println("Set ADMIN_PASSWORD in your environment to pick the password yourself.")
		fmt.Println("=====================================================================")
	}
	return nil
}

func unauthorized(c *fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": msg, "code": 401})
}

func forbidden(c *fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": msg, "code": 403})
}

// Suppress unused import on builds that strip the unused
// reference — `strings` may not be imported by every consumer.
var _ = strings.HasPrefix
