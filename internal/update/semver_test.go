package update

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v1.2.3", "v1.2.3", 0, true},
		{"v1.2.3", "v1.2.4", -1, true},
		{"v1.10.0", "v1.9.9", 1, true},
		{"v2.0.0", "v1.99.99", 1, true},
		{"v1.2.3-rc.1", "v1.2.3", -1, true},
		{"v1.2.3-rc.2", "v1.2.3-rc.10", -1, true},
		{"v1.2.3-alpha", "v1.2.3-alpha.1", -1, true},
		{"v1.2.3-1", "v1.2.3-alpha", -1, true},
		{"v1.2.3+meta", "v1.2.3", 0, true},
		// A Go pseudo-version for a commit after v0.31.0.
		{"v0.31.1-0.20261123010203-abcdef123456", "v0.31.0", 1, true},
		{"v0.31.1-0.20261123010203-abcdef123456", "v0.31.1", -1, true},
		{"(devel)", "v1.0.0", 0, false},
		{"v(dev)", "v1.0.0", 0, false},
		{"v1.2", "v1.2.0", 0, false},
		{"v01.2.3", "v1.2.3", 0, false},
		{"1.2.3", "v1.2.3", 0, false},
		// Pre-release numbers of any size, and invalid identifiers.
		{"v1.0.0-99999999999999999999", "v1.0.0-100000000000000000000", -1, true},
		{"v1.0.0-01", "v1.0.0-1", 0, false},
		{"v1.0.0-a..b", "v1.0.0", 0, false},
		{"v1.0.0-", "v1.0.0", 0, false},
		{"v1.0.0-0a", "v1.0.0-1", 1, true},
		// A pseudo-version on a pre-release base.
		{"v1.2.3-rc.1.0.20261123010203-abcdef123456", "v1.2.3-rc.1", 1, true},
		{"v1.2.3+incompatible", "v1.2.3", 0, true},
	}
	for _, test := range tests {
		got, ok := compareVersions(test.a, test.b)
		if got != test.want || ok != test.ok {
			t.Errorf("compareVersions(%q, %q) = %d, %t; want %d, %t", test.a, test.b, got, ok, test.want, test.ok)
		}
	}
}

func TestIsNewerThan(t *testing.T) {
	tests := []struct {
		version, latest string
		want            bool
	}{
		{"v0.31.0", "v0.30.0", true},
		{"v0.30.0", "v0.31.0", false},
		{"v0.31.0", "v0.31.0", false},
		// A build from the main branch after the latest release.
		{"v0.31.1-0.20261123010203-abcdef123456", "v0.31.0", true},
		// A development build is never newer, so it can still update.
		{"(devel)", "v0.31.0", false},
		{"v(dev)", "v0.31.0", false},
		// A release tag that is not a version does not block an update.
		{"v0.31.0", "nightly", false},
	}
	for _, test := range tests {
		if got := isNewerThan(test.version, test.latest); got != test.want {
			t.Errorf("isNewerThan(%q, %q) = %t, want %t", test.version, test.latest, got, test.want)
		}
	}
}

func TestCompareVersionsPrecedenceChain(t *testing.T) {
	// The example from the Semantic Versioning specification, in order.
	chain := []string{
		"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta",
		"v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0",
	}
	for i := range chain {
		for j := range chain {
			got, ok := compareVersions(chain[i], chain[j])
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if !ok || got != want {
				t.Errorf("compareVersions(%q, %q) = %d, %t; want %d", chain[i], chain[j], got, ok, want)
			}
		}
	}
}
