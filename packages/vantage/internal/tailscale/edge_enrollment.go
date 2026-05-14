package tailscale

import "context"

// MintEdgeEnrollmentAuthKey wraps MintAuthKey with the parameters
// locked by issue #22 Q3 for federation v1's Edge bootstrap flow.
// Centralizing the option set here means the enrollment handler
// (handlers/edge_federation.go) cannot accidentally vary the tags,
// reusability, or expiry — they're a single chokepoint.
//
//   - tags=["tag:vaporrmm-edge"]: a global tag, not per-tenant.
//     Endpoints never join the tailnet (Q4); only Edges do, and
//     per-tenant scoping is enforced at Vantage's application
//     layer via tenant_id columns. A per-tenant Tailscale tag
//     would add ACL pressure without buying isolation that isn't
//     already provided by the app-layer tenant binding.
//
//   - preauthorized=true: the operator already authorized this
//     Edge by minting the enrollment bundle; no separate Tailscale
//     admin approval is needed when the Edge joins.
//
//   - reusable=false: one auth key per enrollment bundle. The
//     bundle is single-use (consumed_at on enrollment_tokens),
//     so reusing the auth key would either be wasted (bundle
//     refused) or unsafe (bundle replayed).
//
//   - ephemeral=false: Edges are long-lived devices. Ephemeral
//     keys get reaped by Tailscale on disconnect, which would
//     evict an Edge that briefly lost connectivity.
//
//   - expirySeconds=86400 (24 hours): matches the enrollment
//     token's own 24h expiry. After both expire together, the
//     operator must mint a fresh bundle.
func (c *Client) MintEdgeEnrollmentAuthKey(ctx context.Context, tailnet, description string) (*AuthKey, error) {
	return c.MintAuthKey(ctx, MintAuthKeyOptions{
		Tailnet:       tailnet,
		Tags:          []string{"tag:vaporrmm-edge"},
		Preauthorized: true,
		Reusable:      false,
		Ephemeral:     false,
		ExpirySeconds: 86400,
		Description:   description,
	})
}
