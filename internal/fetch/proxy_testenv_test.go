package fetch

import (
	"os"
	"strings"
	"testing"
)

// Local HTTP fixtures must opt out explicitly now that proxy selection does
// not apply hidden loopback exceptions. Preserve any caller policy and add the
// loopback addresses used by this package's test servers.
func TestMain(m *testing.M) {
	value := os.Getenv("NO_PROXY")
	if value != "" && !strings.HasSuffix(value, ",") {
		value += ","
	}
	value += "localhost,127.0.0.1,::1"
	_ = os.Setenv("NO_PROXY", value)
	os.Exit(m.Run())
}
