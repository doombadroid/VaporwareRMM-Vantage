package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// captureCookies hits /login on a Fiber app and returns all
// Set-Cookie headers concatenated for keyword inspection.
func captureCookies(t *testing.T) string {
	t.Helper()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/login", func(c *fiber.Ctx) error {
		SetSessionCookies(c, "jwt-test", "csrf-test")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	defer resp.Body.Close()
	return strings.Join(resp.Header.Values("Set-Cookie"), "\n")
}

// TestCookieSecure_DefaultsTrue: with FORCE_SECURE_COOKIES unset,
// SetSessionCookies must mark cookies Secure. The bug codex
// caught was that c.Protocol()-derived Secure returned false when
// Vantage runs behind a TLS-terminating proxy. The new policy is
// "secure unless explicitly opted out".
func TestCookieSecure_DefaultsTrue(t *testing.T) {
	t.Setenv("FORCE_SECURE_COOKIES", "")
	cookies := captureCookies(t)
	if !strings.Contains(cookies, "secure") && !strings.Contains(cookies, "Secure") {
		t.Errorf("expected Secure flag on cookies by default; got %q", cookies)
	}
}

// TestCookieSecure_RespectsOptOut: with FORCE_SECURE_COOKIES=false,
// SetSessionCookies must omit Secure so cookies still stick over
// http://localhost during dev iteration.
func TestCookieSecure_RespectsOptOut(t *testing.T) {
	t.Setenv("FORCE_SECURE_COOKIES", "false")
	cookies := captureCookies(t)
	if strings.Contains(cookies, "secure") || strings.Contains(cookies, "Secure") {
		t.Errorf("FORCE_SECURE_COOKIES=false should drop Secure; got %q", cookies)
	}
}

// TestInit_RefusesHTTPSPublicURLWithInsecureCookies: the sanity
// check refuses to boot when the deployment looks production
// (VANTAGE_PUBLIC_URL is https) but FORCE_SECURE_COOKIES=false —
// the combination would leak auth cookies cleartext.
func TestInit_RefusesHTTPSPublicURLWithInsecureCookies(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "false")
	t.Setenv("VANTAGE_PUBLIC_URL", "https://vantage.example.com")

	err := Init()
	if err == nil {
		t.Fatal("Init should refuse https + insecure cookies combination")
	}
	if !strings.Contains(err.Error(), "FORCE_SECURE_COOKIES") {
		t.Errorf("error should mention the env var; got: %v", err)
	}
}

// TestInit_AcceptsHTTPSPublicURLWithSecureCookies: production-like
// config (https URL + default secure cookies) must boot fine.
func TestInit_AcceptsHTTPSPublicURLWithSecureCookies(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "")
	t.Setenv("VANTAGE_PUBLIC_URL", "https://vantage.example.com")

	if err := Init(); err != nil {
		t.Fatalf("Init should accept https + default secure cookies; got %v", err)
	}
}

// TestInit_AcceptsHTTPPublicURLWithInsecureCookies: dev-like
// config (http URL + opt-out) must boot fine.
func TestInit_AcceptsHTTPPublicURLWithInsecureCookies(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "false")
	t.Setenv("VANTAGE_PUBLIC_URL", "http://localhost:9090")

	if err := Init(); err != nil {
		t.Fatalf("Init should accept dev opt-out + http URL; got %v", err)
	}
}

// VANTAGE_PUBLIC_URL boot validation (codex round-5 #3).

func TestInit_RefusesEmptyPublicURL(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("VANTAGE_PUBLIC_URL", "")
	err := Init()
	if err == nil {
		t.Fatal("Init should refuse empty VANTAGE_PUBLIC_URL")
	}
	if !strings.Contains(err.Error(), "VANTAGE_PUBLIC_URL") {
		t.Errorf("error should name VANTAGE_PUBLIC_URL; got: %v", err)
	}
}

func TestInit_RefusesMalformedPublicURL(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	// No scheme — url.Parse returns Scheme="", Host="".
	t.Setenv("VANTAGE_PUBLIC_URL", "vantage.example.com")
	err := Init()
	if err == nil {
		t.Fatal("Init should refuse malformed URL")
	}
	if !strings.Contains(err.Error(), "not a valid URL") {
		t.Errorf("error should say 'not a valid URL'; got: %v", err)
	}
}

func TestInit_RefusesHTTPInProduction(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "") // default = secure
	t.Setenv("VANTAGE_PUBLIC_URL", "http://vantage.example.com")
	err := Init()
	if err == nil {
		t.Fatal("Init should refuse http URL when FORCE_SECURE_COOKIES is default-true")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement; got: %v", err)
	}
}

func TestInit_AcceptsValidHTTPS(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "")
	t.Setenv("VANTAGE_PUBLIC_URL", "https://vantage.example.com")
	if err := Init(); err != nil {
		t.Fatalf("Init should accept valid https URL; got %v", err)
	}
}

func TestInit_AcceptsHTTPInDevMode(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("FORCE_SECURE_COOKIES", "false")
	t.Setenv("VANTAGE_PUBLIC_URL", "http://localhost:9090")
	if err := Init(); err != nil {
		t.Fatalf("Init should accept http URL in dev mode; got %v", err)
	}
}
