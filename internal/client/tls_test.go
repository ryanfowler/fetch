package client

import (
	"crypto/tls"
	"testing"
)

func TestBuildTLSConfigVersionBounds(t *testing.T) {
	t.Run("defaults to TLS 1.2 minimum", func(t *testing.T) {
		cfg := (&TLSDialConfig{}).BuildTLSConfig()
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %x, want %x", cfg.MinVersion, tls.VersionTLS12)
		}
		if cfg.MaxVersion != 0 {
			t.Fatalf("MaxVersion = %x, want 0", cfg.MaxVersion)
		}
	})

	t.Run("sets explicit min and max", func(t *testing.T) {
		cfg := (&TLSDialConfig{
			TLSMin: tls.VersionTLS12,
			TLSMax: tls.VersionTLS13,
		}).BuildTLSConfig()
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %x, want %x", cfg.MinVersion, tls.VersionTLS12)
		}
		if cfg.MaxVersion != tls.VersionTLS13 {
			t.Fatalf("MaxVersion = %x, want %x", cfg.MaxVersion, tls.VersionTLS13)
		}
	})
}
