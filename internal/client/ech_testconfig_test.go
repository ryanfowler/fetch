package client

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/binary"
	"testing"
)

const (
	testECHVersion   uint16 = 0xfe0d
	testECHKEM       uint16 = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	testECHKDF       uint16 = 0x0001 // HKDF-SHA256
	testECHAES128GCM uint16 = 0x0001
)

// testUnusableECHConfigList returns a valid ECHConfigList with public name
// "public.example" and a fresh key that no test server holds. A server
// rejects the offer, so tests can exercise the rejection paths.
func testUnusableECHConfigList(t *testing.T) []byte {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testECHConfigList(testECHConfig(1, privateKey.PublicKey().Bytes(), "public.example"))
}

func appendUint16(dst []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(dst, value)
}
