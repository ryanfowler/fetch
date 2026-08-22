package client

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"testing"

	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestGenerateGREASEECHConfigList(t *testing.T) {
	first, err := GenerateGREASEECHConfigList()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateGREASEECHConfigList()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two GREASE ECH configurations were identical")
	}
	for _, value := range [][]byte{first, second} {
		if _, err := resolver.SupportedECHConfigList(value); err != nil {
			t.Fatalf("generated ECHConfigList is invalid: %v", err)
		}
		if len(value) < 8 || binary.BigEndian.Uint16(value[2:]) != greaseECHVersion {
			t.Fatalf("generated ECHConfigList has unexpected version: %x", value)
		}
	}
}

func TestGenerateGREASEECHConfigListUsesCryptoTLSConfiguration(t *testing.T) {
	value, err := generateGREASEECHConfigList(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		InsecureSkipVerify:             true, // only parse the client configuration in this test
		EncryptedClientHelloConfigList: value,
	}
	if cfg.EncryptedClientHelloConfigList == nil {
		t.Fatal("ECHConfigList was not installed")
	}
	if _, err := resolver.SupportedECHConfigList(cfg.EncryptedClientHelloConfigList); err != nil {
		t.Fatalf("TLS configuration contains invalid ECHConfigList: %v", err)
	}
}
