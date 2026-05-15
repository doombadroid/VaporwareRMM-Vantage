package handlers

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"
)

// ValidateMinEdgeVersion checks the MINIMUM_REQUIRED_EDGE_VERSION
// env var at boot time. Empty = no version gating. Anything else
// must parse as semver; invalid values would otherwise produce a
// confused 400 "malformed edge_version" response on every poll/
// register, attributed to the client even though the server is
// misconfigured. Codex finding #5/#6 flagged both ends of this.
//
// main.go calls this before the HTTP server starts. A failed
// check exits with a remediation message rather than booting into
// a broken state.
func ValidateMinEdgeVersion() error {
	raw := os.Getenv("MINIMUM_REQUIRED_EDGE_VERSION")
	if raw == "" {
		return nil
	}
	candidate := ensureV(raw)
	if !semver.IsValid(candidate) {
		return fmt.Errorf(
			"MINIMUM_REQUIRED_EDGE_VERSION=%q is not a valid semver; set to a value like 0.1.0 or v0.1.0, or unset to disable version gating",
			raw,
		)
	}
	return nil
}

// versionAtLeast reports whether candidate >= minimum using
// golang.org/x/mod/semver — which implements SemVer 2.0.0
// comparison rules. Prerelease identifiers compare numerically
// when numeric ("rc.10" > "rc.2"), lexically otherwise, and any
// prerelease is less than its base version ("1.0.0-rc.1" <
// "1.0.0").
//
// Codex finding #5 flagged the hand-rolled comparison that
// treated prerelease tags as raw strings — under that scheme
// "rc.10" sorted before "rc.2".
//
// x/mod/semver requires a "v" prefix on the input strings. We
// add one if missing so the federation wire format ("0.1.0",
// "1.0.0-rc.1") works directly.
func versionAtLeast(candidate, minimum string) (bool, error) {
	if candidate == "" {
		return false, errors.New("missing version")
	}
	c := ensureV(candidate)
	if !semver.IsValid(c) {
		return false, errors.New("invalid version: " + candidate)
	}
	if minimum == "" {
		// Candidate parse already done; no floor configured so
		// nothing to compare against. Accept.
		return true, nil
	}
	m := ensureV(minimum)
	if !semver.IsValid(m) {
		// ValidateMinEdgeVersion runs at boot; this branch is
		// only reachable if the env var was changed mid-process
		// (unusual). Still classify as server-side.
		return false, errors.New("invalid minimum: " + minimum)
	}
	return semver.Compare(c, m) >= 0, nil
}

func ensureV(s string) string {
	if !strings.HasPrefix(s, "v") {
		return "v" + s
	}
	return s
}
