package handlers

// F4a: tag metadata mirror (issue #22 Q7). The Edge is the source of truth
// for which endpoints exist and how they are tagged; Vantage mirrors that
// membership so it can expand a tag target into explicit endpoint_ids at
// command-enqueue time. The Edge POSTs its full tag set here whenever its
// local tag/endpoint state changes (plus a periodic sanity sync).
//
// The sync is "wipe and replace" for this Edge, in one transaction: simple,
// and correct under the Edge being the single writer for its own rows. A
// little state churn per sync is acceptable for v1 — syncs are infrequent.

import (
	"fmt"

	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Bounded-input guards (no unbounded INSERT in one transaction). Generous
// for real fleets; a malformed/hostile Edge can't make us churn unboundedly.
const (
	maxTagsPerSync        = 1000
	maxMembershipsPerSync = 100000
	// tagSyncLockNamespace is the classid for the per-edge tag-sync advisory
	// lock (pg_advisory_xact_lock(classid, objid)); objid is hashtext(edge_id).
	// Arbitrary but stable; distinct lock space from any single-key advisory lock.
	tagSyncLockNamespace = 0x54475953 // "TGYS"
)

func postEdgeTagsSync(c *fiber.Ctx) error {
	// ---- Phase 1: parse + validate (no DB writes) ----
	var req struct {
		Tags []struct {
			Name        string   `json:"name"`
			EndpointIDs []string `json:"endpoint_ids"`
		} `json:"tags"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if len(req.Tags) > maxTagsPerSync {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("tag count %d exceeds max %d", len(req.Tags), maxTagsPerSync),
		})
	}
	// Validate names: non-empty and unique within the batch (the schema's
	// UNIQUE(edge_id,name) would reject dupes mid-transaction, but catching
	// it here returns a clear 400 instead of a 500).
	seenName := make(map[string]bool, len(req.Tags))
	totalMemberships := 0
	for _, tg := range req.Tags {
		if tg.Name == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tag name must not be empty"})
		}
		if seenName[tg.Name] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("duplicate tag name in request: %q", tg.Name),
			})
		}
		seenName[tg.Name] = true
		totalMemberships += len(tg.EndpointIDs)
	}
	if totalMemberships > maxMembershipsPerSync {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("membership count %d exceeds max %d", totalMemberships, maxMembershipsPerSync),
		})
	}

	edgeID, _ := c.Locals("edge_id").(string)
	tenantID, _ := c.Locals("tenant_id").(string)

	// ---- Phase 3: single transaction wraps all writes ----
	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize concurrent full syncs for THIS edge (codex round 4). Two
	// overlapping wipe/replace syncs under READ COMMITTED can interleave so the
	// second's DELETE runs before the first's replacement rows are visible —
	// leaving stale tags (which would mis-expand command targets) or colliding
	// on UNIQUE(edge_id,name) with a 500. A per-edge advisory xact lock
	// serializes them cluster-wide (released on commit/rollback). The two-arg
	// form uses a distinct lock space from the audit chain's single-key lock,
	// so they never contend.
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1, hashtext($2))`, tagSyncLockNamespace, edgeID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "lock acquire failed"})
	}

	// Wipe this Edge's tags. membership rows cascade via the FK ON DELETE
	// CASCADE, but delete them explicitly first so the intent is plain and
	// the operation doesn't depend on cascade ordering.
	if _, err := tx.Exec(`DELETE FROM tag_endpoint_membership WHERE tag_id IN (SELECT id FROM tags WHERE edge_id = $1)`, edgeID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tag membership wipe failed"})
	}
	if _, err := tx.Exec(`DELETE FROM tags WHERE edge_id = $1`, edgeID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tag wipe failed"})
	}

	syncedTags := 0
	syncedMemberships := 0
	for _, tg := range req.Tags {
		tagID := uuid.New().String()
		if _, err := tx.Exec(`INSERT INTO tags (id, tenant_id, edge_id, name) VALUES ($1, $2, $3, $4)`,
			tagID, tenantID, edgeID, tg.Name); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tag insert failed"})
		}
		syncedTags++
		// Dedup endpoint_ids within a tag to avoid the (tag_id,endpoint_id)
		// PK violation on a repeated endpoint.
		seenEP := make(map[string]bool, len(tg.EndpointIDs))
		for _, ep := range tg.EndpointIDs {
			if ep == "" || seenEP[ep] {
				continue
			}
			seenEP[ep] = true
			if _, err := tx.Exec(`INSERT INTO tag_endpoint_membership (tag_id, endpoint_id) VALUES ($1, $2)`, tagID, ep); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "membership insert failed"})
			}
			syncedMemberships++
		}
	}

	if err := events.AuditLogSyncTx(tx, "", "edge.tags.sync", "edge", edgeID,
		fmt.Sprintf("tags=%d memberships=%d", syncedTags, syncedMemberships), c.IP()); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "audit write failed"})
	}

	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "commit failed"})
	}

	// ---- Phase 4: response ----
	return c.JSON(fiber.Map{
		"synced_tags":        syncedTags,
		"synced_memberships": syncedMemberships,
	})
}
