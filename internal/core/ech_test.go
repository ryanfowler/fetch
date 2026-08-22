package core

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestValidateECHPolicy(t *testing.T) {
	tests := []struct {
		name    string
		mode    ECHMode
		http    HTTPVersion
		min     uint16
		max     uint16
		wantErr string
	}{
		{name: "off permits all", mode: ECHOff, http: HTTP3, min: tls.VersionTLS12, max: tls.VersionTLS12},
		{name: "auto permits HTTP3", mode: ECHAuto, http: HTTP3},
		{name: "on permits TCP", mode: ECHOn, http: HTTP2},
		{name: "on rejects explicit HTTP3", mode: ECHOn, http: HTTP3, wantErr: "explicit HTTP/3"},
		{name: "explicit TLS minimum 1.2", mode: ECHAuto, min: tls.VersionTLS12, wantErr: "TLS 1.3"},
		{name: "explicit TLS maximum 1.2", mode: ECHOn, max: tls.VersionTLS12, wantErr: "TLS 1.3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateECHPolicy(test.mode, test.http, test.min, test.max)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
