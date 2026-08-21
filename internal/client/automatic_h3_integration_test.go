package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAutomaticHTTPSFallsBackToTCPWithoutSendingTwice(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "")
	}
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c := NewClient(ClientConfig{Insecure: true})
	defer c.Close()
	if _, ok := c.HTTPClient().Transport.(*automaticHTTP3Transport); !ok {
		t.Skip("automatic HTTP/3 is disabled by the host proxy environment")
	}
	url := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	resp, err := c.HTTPClient().Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if requests != 1 {
		t.Fatalf("server saw %d requests, want one", requests)
	}
}
