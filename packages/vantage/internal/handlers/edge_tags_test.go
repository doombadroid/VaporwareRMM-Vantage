package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
)

func callTagsSync(t *testing.T, app *fiber.App, token string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/edge/tags/sync", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func tagCounts(t *testing.T, edgeID string) (tags, memberships int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM tags WHERE edge_id = $1`, edgeID).Scan(&tags); err != nil {
		t.Fatalf("count tags: %v", err)
	}
	if err := db.DB.QueryRow(
		`SELECT COUNT(*) FROM tag_endpoint_membership tem JOIN tags t ON t.id = tem.tag_id WHERE t.edge_id = $1`, edgeID,
	).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	return tags, memberships
}

func TestEdgeTagsSync_WipeAndReplace(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-tags", "tenant-x", time.Hour)

	// First sync: two tags, three memberships.
	resp := callTagsSync(t, app, tok, map[string]any{"tags": []map[string]any{
		{"name": "linux-prod", "endpoint_ids": []string{"h1", "h2"}},
		{"name": "win-stage", "endpoint_ids": []string{"h3"}},
	}})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first sync status=%d", resp.StatusCode)
	}
	var out struct {
		SyncedTags        int `json:"synced_tags"`
		SyncedMemberships int `json:"synced_memberships"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.SyncedTags != 2 || out.SyncedMemberships != 3 {
		t.Fatalf("first sync = %+v, want tags=2 memberships=3", out)
	}
	if tg, mm := tagCounts(t, "edge-tags"); tg != 2 || mm != 3 {
		t.Fatalf("after first sync rows: tags=%d memberships=%d, want 2/3", tg, mm)
	}

	// Second sync REPLACES: one tag, one membership. Old state wiped.
	resp2 := callTagsSync(t, app, tok, map[string]any{"tags": []map[string]any{
		{"name": "linux-prod", "endpoint_ids": []string{"h1"}},
	}})
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("second sync status=%d", resp2.StatusCode)
	}
	if tg, mm := tagCounts(t, "edge-tags"); tg != 1 || mm != 1 {
		t.Errorf("after replace: tags=%d memberships=%d, want 1/1 (old wiped)", tg, mm)
	}
}

func TestEdgeTagsSync_DedupesEndpointIDs(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-dedup", "tenant-x", time.Hour)
	resp := callTagsSync(t, app, tok, map[string]any{"tags": []map[string]any{
		{"name": "t1", "endpoint_ids": []string{"h1", "h1", "h2", ""}}, // dup + empty
	}})
	defer resp.Body.Close()
	var out struct {
		SyncedMemberships int `json:"synced_memberships"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.SyncedMemberships != 2 {
		t.Errorf("synced_memberships = %d, want 2 (h1 deduped, empty skipped)", out.SyncedMemberships)
	}
}

func TestEdgeTagsSync_RejectsEmptyAndDuplicateNames(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-bad", "tenant-x", time.Hour)

	empty := callTagsSync(t, app, tok, map[string]any{"tags": []map[string]any{{"name": "", "endpoint_ids": []string{}}}})
	defer empty.Body.Close()
	if empty.StatusCode != 400 {
		t.Errorf("empty name: status=%d, want 400", empty.StatusCode)
	}

	dup := callTagsSync(t, app, tok, map[string]any{"tags": []map[string]any{
		{"name": "same", "endpoint_ids": []string{"h1"}},
		{"name": "same", "endpoint_ids": []string{"h2"}},
	}})
	defer dup.Body.Close()
	if dup.StatusCode != 400 {
		t.Errorf("duplicate name: status=%d, want 400", dup.StatusCode)
	}
}

// TestEdgeTagsSync_ConcurrentSameEdge: overlapping full syncs for one edge must
// all succeed without a UNIQUE(edge_id,name) race (codex round 4). The per-edge
// advisory lock serializes them; final state is one sync's worth, no 500s.
func TestEdgeTagsSync_ConcurrentSameEdge(t *testing.T) {
	app := edgeFederationEnv(t) // DB setup
	_ = app
	tok := seedEdgeForPoll(t, "edge-cc", "tenant-x", time.Hour)

	const n = 8
	var wg sync.WaitGroup
	statuses := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Separate app per goroutine — a single fiber app.Test is not meant
			// to be driven concurrently; they share the global db.DB.
			a := fiber.New(fiber.Config{DisableStartupMessage: true})
			RegisterEdgeRoutes(a)
			b, _ := json.Marshal(map[string]any{"tags": []map[string]any{
				{"name": "t1", "endpoint_ids": []string{"h" + strconv.Itoa(i)}},
				{"name": "t2", "endpoint_ids": []string{"hx"}},
			}})
			req := httptest.NewRequest(http.MethodPost, "/api/edge/tags/sync", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := a.Test(req, -1)
			if err != nil {
				errs[i] = err
				return
			}
			statuses[i] = resp.StatusCode
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("sync %d errored: %v", i, errs[i])
		}
		if statuses[i] != 200 {
			t.Errorf("concurrent sync %d: status=%d, want 200 (no UNIQUE race under the per-edge lock)", i, statuses[i])
		}
	}
	// UNIQUE(edge_id,name) guarantees ≤1 of each name; with serialization the
	// final state is exactly one sync's set: t1 + t2.
	var nt int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM tags WHERE edge_id='edge-cc'`).Scan(&nt); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nt != 2 {
		t.Errorf("final tag count=%d, want 2 (t1,t2)", nt)
	}
}

func TestEdgeTagsSync_RequiresAuth(t *testing.T) {
	app := edgeFederationEnv(t)
	resp := callTagsSync(t, app, "", map[string]any{"tags": []map[string]any{}})
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("no token: status=%d, want 401", resp.StatusCode)
	}
}

func TestEdgeTagsSync_IsolatedPerEdge(t *testing.T) {
	app := edgeFederationEnv(t)
	tokA := seedEdgeForPoll(t, "edge-A", "tenant-x", time.Hour)
	tokB := seedEdgeForPoll(t, "edge-B", "tenant-x", time.Hour)

	respA := callTagsSync(t, app, tokA, map[string]any{"tags": []map[string]any{{"name": "a-tag", "endpoint_ids": []string{"h1"}}}})
	respA.Body.Close()
	respB := callTagsSync(t, app, tokB, map[string]any{"tags": []map[string]any{{"name": "b-tag", "endpoint_ids": []string{"h2"}}}})
	respB.Body.Close()

	// B's sync must not have wiped A's tags.
	if tg, _ := tagCounts(t, "edge-A"); tg != 1 {
		t.Errorf("edge-A tags=%d after edge-B sync, want 1 (per-edge isolation)", tg)
	}
	if tg, _ := tagCounts(t, "edge-B"); tg != 1 {
		t.Errorf("edge-B tags=%d, want 1", tg)
	}
}
