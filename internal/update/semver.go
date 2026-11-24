package update

import (
	"strconv"
	"strings"
)

// compareVersions compares two semantic versions such as "v1.2.3",
// "v1.2.3-rc.1", or a Go pseudo-version. It returns -1, 0, or +1, and false
// when either value is not a semantic version, such as "(devel)". Build
// metadata after "+" is ignored, as Semantic Versioning requires.
func compareVersions(a, b string) (int, bool) {
	va, ok := parseVersion(a)
	if !ok {
		return 0, false
	}
	vb, ok := parseVersion(b)
	if !ok {
		return 0, false
	}
	for i := range va.core {
		if va.core[i] != vb.core[i] {
			if va.core[i] < vb.core[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return comparePrerelease(va.pre, vb.pre), true
}

type version struct {
	core [3]uint64
	pre  []string
}

func parseVersion(s string) (version, bool) {
	s, ok := strings.CutPrefix(s, "v")
	if !ok {
		return version{}, false
	}
	s, _, _ = strings.Cut(s, "+")
	s, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	var v version
	for i, part := range parts {
		n, ok := parseNumericIdentifier(part)
		if !ok {
			return version{}, false
		}
		v.core[i] = n
	}
	if hasPre {
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			// An identifier is not empty, and a numeric one has no leading
			// zero.
			if id == "" || (len(id) > 1 && id[0] == '0' && isDigits(id)) {
				return version{}, false
			}
		}
	}
	return v, true
}

// parseNumericIdentifier parses a number without a leading zero.
func parseNumericIdentifier(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// isDigits reports whether s is not empty and has only ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumeric compares two digit strings without leading zeros of any
// length: a longer number is larger.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// comparePrerelease compares pre-release identifiers. A version without a
// pre-release is greater than one with a pre-release.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		aNumeric, bNumeric := isDigits(a[i]), isDigits(b[i])
		var c int
		switch {
		case aNumeric && bNumeric:
			c = compareNumeric(a[i], b[i])
		case aNumeric:
			c = -1 // numeric identifiers sort before alphanumeric ones
		case bNumeric:
			c = 1
		default:
			c = strings.Compare(a[i], b[i])
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
