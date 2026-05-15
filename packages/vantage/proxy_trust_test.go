package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// Codex round-7 #1/#2: trusted proxy + X-Forwarded-For tests.

func TestParseTrustedProxies_Empty(t *testing.T) {
	got, err := parseTrustedProxies("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("empty CSV should return nil slice; got %v", got)
	}
}

func TestParseTrustedProxies_ValidCIDRs(t *testing.T) {
	got, err := parseTrustedProxies("127.0.0.1/32, ::1/128 ,10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8"}
	if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTrustedProxies_BareIPsPromotedToCIDR(t *testing.T) {
	got, err := parseTrustedProxies("127.0.0.1,::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1/32", "::1/128"}
	if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTrustedProxies_InvalidCIDRReturnsError(t *testing.T) {
	for _, bad := range []string{"not-a-cidr", "300.300.300.300/32", "127.0.0.1/99"} {
		t.Run(bad, func(t *testing.T) {
			_, err := parseTrustedProxies(bad)
			if err == nil {
				t.Errorf("parseTrustedProxies(%q) should error", bad)
			}
		})
	}
}

func TestBuildFiberConfig_TrustedProxiesUnset_DoesNotSetProxyHeader(t *testing.T) {
	cfg, err := buildFiberConfig("", "https://vantage.test.local")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.EnableTrustedProxyCheck {
		t.Error("EnableTrustedProxyCheck should be false when TRUSTED_PROXIES is empty")
	}
	if cfg.ProxyHeader != "" {
		t.Errorf("ProxyHeader must NOT be set when no trusted proxies — would allow spoofing; got %q", cfg.ProxyHeader)
	}
	if cfg.EnableIPValidation {
		t.Error("EnableIPValidation should be off when not using proxy headers (no header to validate)")
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies should be empty, got %v", cfg.TrustedProxies)
	}
}

func TestBuildFiberConfig_TrustedProxiesSet_EnablesAndValidates(t *testing.T) {
	cfg, err := buildFiberConfig("127.0.0.1/32,::1/128", "https://vantage.test.local")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !cfg.EnableTrustedProxyCheck {
		t.Error("EnableTrustedProxyCheck should be true when TRUSTED_PROXIES is set")
	}
	if cfg.ProxyHeader != fiber.HeaderXForwardedFor {
		t.Errorf("ProxyHeader should be X-Forwarded-For, got %q", cfg.ProxyHeader)
	}
	if !cfg.EnableIPValidation {
		t.Error("EnableIPValidation must be true to reject malformed X-Forwarded-For chains")
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("TrustedProxies length: got %d, want 2", len(cfg.TrustedProxies))
	}
}

func TestBuildFiberConfig_InvalidCIDR_ReturnsError(t *testing.T) {
	_, err := buildFiberConfig("not-a-cidr", "https://vantage.test.local")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
		t.Errorf("error should mention TRUSTED_PROXIES; got %v", err)
	}
}

// serveOnTCP starts a Fiber app on a real localhost listener so
// the test client connects from 127.0.0.1, surfacing a real
// RemoteAddr to Fiber's trusted-proxy logic. app.Test's in-memory
// transport doesn't propagate RemoteAddr, so end-to-end XFF
// behavior must be exercised over actual TCP.
func serveOnTCP(t *testing.T, trustedProxiesCSV string) (baseURL string, stop func()) {
	t.Helper()
	cfg, err := buildFiberConfig(trustedProxiesCSV, "https://vantage.test.local")
	if err != nil {
		t.Fatalf("buildFiberConfig: %v", err)
	}
	app := fiber.New(cfg)
	app.Get("/whoami", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ip": c.IP()})
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		_ = app.Listener(ln)
	}()
	return "http://" + ln.Addr().String(), func() {
		_ = app.Shutdown()
	}
}

func ipOfHTTP(t *testing.T, baseURL, xff string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/whoami", nil)
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.IP
}

func TestFiberConfig_TrustedProxiesUnset_IgnoresForwardedFor(t *testing.T) {
	base, stop := serveOnTCP(t, "")
	defer stop()
	got := ipOfHTTP(t, base, "1.2.3.4")
	if got == "1.2.3.4" {
		t.Errorf("untrusted X-Forwarded-For must be ignored; c.IP() should NOT be the header value, got %q", got)
	}
	if got != "127.0.0.1" {
		t.Errorf("c.IP() should be socket peer (127.0.0.1) when XFF untrusted; got %q", got)
	}
}

func TestFiberConfig_TrustedProxiesSet_HonorsForwardedFor(t *testing.T) {
	base, stop := serveOnTCP(t, "127.0.0.1/32")
	defer stop()
	got := ipOfHTTP(t, base, "1.2.3.4")
	if got != "1.2.3.4" {
		t.Errorf("trusted peer's X-Forwarded-For should surface; want 1.2.3.4, got %q", got)
	}
}

func TestFiberConfig_TrustedProxiesSet_RejectsForwardedForFromUntrustedPeer(t *testing.T) {
	// Trust an IP range that does NOT include the loopback the
	// test client dials from. Fiber should treat 127.0.0.1 as an
	// untrusted peer and ignore XFF.
	base, stop := serveOnTCP(t, "10.0.0.0/8")
	defer stop()
	got := ipOfHTTP(t, base, "1.2.3.4")
	if got == "1.2.3.4" {
		t.Errorf("untrusted peer must not be allowed to spoof via X-Forwarded-For; got %q", got)
	}
	if got != "127.0.0.1" {
		t.Errorf("expected socket peer 127.0.0.1, got %q", got)
	}
}

// TestRateLimit_SpoofingAttempt_Defeated: the contract test for
// the security fix. With TRUSTED_PROXIES unset, X-Forwarded-For is
// ignored. 31 requests from the same socket peer with different
// X-Forwarded-For values must all bucket on the socket peer →
// first 30 reach the handler, 31st gets 429. If the bug was
// present (untrusted XFF honored), each request would land in its
// own bucket and all 31 would succeed.
func TestRateLimit_SpoofingAttempt_Defeated(t *testing.T) {
	cfg, err := buildFiberConfig("", "https://vantage.test.local")
	if err != nil {
		t.Fatalf("buildFiberConfig: %v", err)
	}
	app := fiber.New(cfg)
	ipLimiter := limiter.New(limiter.Config{
		Max:        30,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return "ip:" + c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "rate limit"})
		},
	})
	app.Post("/test", ipLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	statuses := make([]int, 31)
	for i := 0; i < 31; i++ {
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(nil))
		req.RemoteAddr = "5.6.7.8:55555"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("1.2.3.%d", i+1))
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("Test request %d: %v", i, err)
		}
		statuses[i] = resp.StatusCode
		resp.Body.Close()
	}
	ok, limited := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if ok != 30 {
		t.Errorf("expected 30 × 200 (all bucketed on socket peer), got %d (statuses: %v)", ok, statuses)
	}
	if limited != 1 {
		t.Errorf("expected 1 × 429 from per-IP limit; if header spoofing worked, all 31 would 200 — got %d (statuses: %v)", limited, statuses)
	}
}

// TestFiberConfig_IPValidation_RejectsMalformedForwardedFor: with
// trusted proxies set and EnableIPValidation, a header carrying
// garbage between commas should resolve to the first valid IP
// rather than the raw string.
func TestFiberConfig_IPValidation_RejectsMalformedForwardedFor(t *testing.T) {
	base, stop := serveOnTCP(t, "127.0.0.1/32")
	defer stop()
	got := ipOfHTTP(t, base, "1.2.3.4, evil-host, 5.6.7.8")
	if got != "1.2.3.4" {
		t.Errorf("expected leftmost valid IP 1.2.3.4 from validated chain, got %q", got)
	}
}
