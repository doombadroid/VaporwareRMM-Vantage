package handlers

import "testing"

// TestVersionAtLeast covers the SemVer rules the federation
// handshake relies on. Prerelease ordering is the key fix from
// codex finding #5 — the hand-rolled lexicographic compare in
// the original implementation got "rc.10" vs "rc.2" wrong.
func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		minimum   string
		want      bool
	}{
		{"equal patch", "0.1.0", "0.1.0", true},
		{"higher patch", "0.1.1", "0.1.0", true},
		{"lower patch", "0.0.9", "0.1.0", false},
		{"higher major", "1.0.0", "0.9.99", true},
		{"lower major", "0.9.99", "1.0.0", false},
		{"prerelease lt release", "1.0.0-rc.1", "1.0.0", false},
		{"release gt prerelease", "1.0.0", "1.0.0-rc.1", true},
		{"prerelease numeric rc.10 gt rc.2", "1.0.0-rc.10", "1.0.0-rc.2", true},
		{"prerelease numeric rc.2 lt rc.10", "1.0.0-rc.2", "1.0.0-rc.10", false},
		{"alpha lt rc", "1.0.0-alpha", "1.0.0-rc", false},
		// Per SemVer 2.0.0 §11: numeric identifiers have lower
		// precedence than alphanumeric. So in "alpha.1" the "1" is
		// numeric < the "beta" in "alpha.beta", which means
		// alpha.beta > alpha.1. Spec example:
		//   1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta
		{"alpha.beta gt alpha.1 per spec", "1.0.0-alpha.beta", "1.0.0-alpha.1", true},
		{"alpha.1 lt alpha.beta per spec", "1.0.0-alpha.1", "1.0.0-alpha.beta", false},
		{"empty minimum accepts anything", "0.0.1", "", true},
		{"v prefix tolerated on candidate", "v0.1.0", "0.1.0", true},
		{"v prefix tolerated on minimum", "0.1.0", "v0.1.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := versionAtLeast(tc.candidate, tc.minimum)
			if err != nil {
				t.Fatalf("versionAtLeast(%q, %q) returned err=%v", tc.candidate, tc.minimum, err)
			}
			if got != tc.want {
				t.Errorf("versionAtLeast(%q, %q) = %v, want %v", tc.candidate, tc.minimum, got, tc.want)
			}
		})
	}
}

func TestVersionAtLeast_RejectsMalformed(t *testing.T) {
	for _, bad := range []string{"not-a-version", "1.0.x", "1..0"} {
		if _, err := versionAtLeast(bad, "0.1.0"); err == nil {
			t.Errorf("versionAtLeast(%q, ...) should reject malformed candidate", bad)
		}
	}
}

func TestVersionAtLeast_MissingCandidate(t *testing.T) {
	if _, err := versionAtLeast("", "0.1.0"); err == nil {
		t.Error("missing candidate should error when minimum is set")
	}
}
