package tailscale

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestMintEdgeEnrollmentAuthKey_LocksFederationOptions asserts the
// helper sends Tailscale exactly the opts that issue #22 Q3 locked.
// If a future PR loosens any of these (tags, reusable, ephemeral,
// preauthorized, expiry) it has to update this test, which forces
// the change through code review.
func TestMintEdgeEnrollmentAuthKey_LocksFederationOptions(t *testing.T) {
	var capturedBody string
	srv, c := fakeTailscale(t, map[string]http.HandlerFunc{
		"POST /api/v2/oauth/token": tokenResponse(),
		"POST /api/v2/tailnet/acme.ts.net/keys": func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			capturedBody = string(b)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "k-edge-enrollment",
				"key":     "tskey-auth-edge-XXXXX",
				"created": "2026-05-14T00:00:00Z",
				"expires": "2026-05-15T00:00:00Z",
			})
		},
	})
	_ = srv

	k, err := c.MintEdgeEnrollmentAuthKey(context.Background(), "acme.ts.net", "ACME Corp HQ enrollment")
	if err != nil {
		t.Fatalf("MintEdgeEnrollmentAuthKey: %v", err)
	}
	if k.Key != "tskey-auth-edge-XXXXX" || k.ID != "k-edge-enrollment" {
		t.Errorf("auth key shape unexpected: %+v", k)
	}

	var sent struct {
		Capabilities struct {
			Devices struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Preauthorized bool     `json:"preauthorized"`
					Tags          []string `json:"tags"`
				} `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
		ExpirySeconds int    `json:"expirySeconds"`
		Description   string `json:"description"`
	}
	if err := json.Unmarshal([]byte(capturedBody), &sent); err != nil {
		t.Fatalf("decode sent body: %v body=%s", err, capturedBody)
	}
	create := sent.Capabilities.Devices.Create
	if create.Reusable {
		t.Error("reusable must be false (single-use bundle)")
	}
	if create.Ephemeral {
		t.Error("ephemeral must be false (Edges are long-lived)")
	}
	if !create.Preauthorized {
		t.Error("preauthorized must be true (operator already authorized)")
	}
	if len(create.Tags) != 1 || create.Tags[0] != "tag:vaporrmm-edge" {
		t.Errorf("tags must be exactly [tag:vaporrmm-edge], got %v", create.Tags)
	}
	if sent.ExpirySeconds != 86400 {
		t.Errorf("expirySeconds must be 86400, got %d", sent.ExpirySeconds)
	}
	if !strings.Contains(sent.Description, "ACME Corp HQ") {
		t.Errorf("description should carry operator's free-form note, got %q", sent.Description)
	}
}
