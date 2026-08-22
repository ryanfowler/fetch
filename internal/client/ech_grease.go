package client

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	greaseECHVersion       uint16 = 0xfe0d
	greaseECHKEM           uint16 = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	greaseECHKDF           uint16 = 0x0001 // HKDF-SHA256
	greaseECHAES128GCM     uint16 = 0x0001
	greaseECHMaxNameLength byte   = 32
)

var greaseECHPublicName = []byte("public.example")

// GenerateGREASEECHConfigList returns a syntactically valid, deliberately
// unusable ECHConfigList. Go's TLS client uses the generated public key to
// construct the ECH extension, while a server that does not have the matching
// private key rejects the offer. This lets callers exercise ECH-capable paths
// without pretending that ECH is available when DNS did not advertise it.
//
// The list is generated for each connection. In particular, neither the
// config ID nor the public key is reused between requests.
func GenerateGREASEECHConfigList() ([]byte, error) {
	return generateGREASEECHConfigList(cryptorand.Reader)
}

func generateGREASEECHConfigList(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, fmt.Errorf("ECH GREASE random source is nil")
	}
	var configID [1]byte
	if _, err := io.ReadFull(random, configID[:]); err != nil {
		return nil, fmt.Errorf("generate ECH GREASE config ID: %w", err)
	}
	privateKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("generate ECH GREASE public key: %w", err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	if len(publicKey) > 0xffff {
		return nil, fmt.Errorf("ECH GREASE public key is too large")
	}

	contents := make([]byte, 0, 64+len(greaseECHPublicName))
	contents = append(contents, configID[0])
	contents = appendUint16(contents, greaseECHKEM)
	contents = appendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	// One supported KDF/AEAD pair: HKDF-SHA256/AES-128-GCM.
	contents = appendUint16(contents, 4)
	contents = appendUint16(contents, greaseECHKDF)
	contents = appendUint16(contents, greaseECHAES128GCM)
	contents = append(contents, greaseECHMaxNameLength)
	contents = append(contents, byte(len(greaseECHPublicName)))
	contents = append(contents, greaseECHPublicName...)
	// No extensions are needed for a GREASE configuration.
	contents = appendUint16(contents, 0)
	if len(contents) > 0xffff {
		return nil, fmt.Errorf("ECH GREASE config is too large")
	}

	config := make([]byte, 0, 4+len(contents))
	config = appendUint16(config, greaseECHVersion)
	config = appendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	if len(config) > 0xffff {
		return nil, fmt.Errorf("ECH GREASE config list is too large")
	}
	list := make([]byte, 0, 2+len(config))
	list = appendUint16(list, uint16(len(config)))
	list = append(list, config...)
	return list, nil
}

func appendUint16(dst []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(dst, encoded[:]...)
}
