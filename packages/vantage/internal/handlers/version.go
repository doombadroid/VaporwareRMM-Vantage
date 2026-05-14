package handlers

import (
	"errors"
	"strconv"
	"strings"
)

// versionAtLeast reports whether candidate >= minimum, comparing
// dotted-integer components left to right. Supports "X.Y.Z" with
// an optional "-prerelease" suffix that's compared lexicographically
// after the numeric components match.
//
// Imported semver libraries would be over-spec for what F2 needs:
// the federation handshake carries plain "0.1.0"-style strings, no
// build metadata, no module-path "v" prefixes.
//
// Errors: malformed candidate ("not a version") returns false +
// error so the handler can surface a precise 400 instead of a
// silent comparison.
func versionAtLeast(candidate, minimum string) (bool, error) {
	if minimum == "" {
		// No floor configured — every Edge passes.
		return true, nil
	}
	if candidate == "" {
		return false, errors.New("missing version")
	}
	cMain, cPre := splitPre(candidate)
	mMain, mPre := splitPre(minimum)
	cParts, err := parseNums(cMain)
	if err != nil {
		return false, err
	}
	mParts, err := parseNums(mMain)
	if err != nil {
		return false, err
	}
	for i := 0; i < len(cParts) || i < len(mParts); i++ {
		var a, b int
		if i < len(cParts) {
			a = cParts[i]
		}
		if i < len(mParts) {
			b = mParts[i]
		}
		if a < b {
			return false, nil
		}
		if a > b {
			return true, nil
		}
	}
	// Numeric parts equal. Pre-release ordering: absent > present
	// (1.0.0 > 1.0.0-rc1), and within-pre-release lexicographic
	// comparison.
	if cPre == "" && mPre != "" {
		return true, nil
	}
	if cPre != "" && mPre == "" {
		return false, nil
	}
	return cPre >= mPre, nil
}

func splitPre(v string) (main, pre string) {
	if i := strings.Index(v, "-"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func parseNums(v string) ([]int, error) {
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, errors.New("version component not numeric: " + p)
		}
		out[i] = n
	}
	return out, nil
}
