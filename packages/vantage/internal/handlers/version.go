package handlers

import (
	"errors"
	"strings"

	"golang.org/x/mod/semver"
)

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
	if minimum == "" {
		return true, nil
	}
	if candidate == "" {
		return false, errors.New("missing version")
	}
	c := ensureV(candidate)
	m := ensureV(minimum)
	if !semver.IsValid(c) {
		return false, errors.New("invalid version: " + candidate)
	}
	if !semver.IsValid(m) {
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
