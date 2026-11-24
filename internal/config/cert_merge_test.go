package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCertificatePEM returns a self-signed certificate and its private key
// as PEM.
func testCertificatePEM(t *testing.T, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestMergeKeepsCombinedCertificateKey(t *testing.T) {
	hostCert, hostKey := testCertificatePEM(t, "host")
	globalCert, globalKey := testCertificatePEM(t, "global")

	// A host section (or the CLI) gives a file with the certificate and its
	// key. The global key belongs to another certificate and must not be
	// paired with it.
	host := &Config{CertData: append(hostCert, hostKey...), CertPath: "combined.pem"}
	global := &Config{CertData: globalCert, CertPath: "global.crt", KeyData: globalKey, KeyPath: "global.key"}
	host.Merge(global)
	if host.KeyData != nil {
		t.Fatalf("combined certificate took the global key %q", host.KeyPath)
	}
	cert, err := host.ClientCert()
	if err != nil {
		t.Fatalf("ClientCert() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.Subject.CommonName != "host" {
		t.Fatalf("client certificate = %v, %v; want the host certificate", leaf, err)
	}

	// A certificate without a key still takes the key of a lower scope.
	cli := &Config{CertData: hostCert, CertPath: "host.crt"}
	cli.Merge(&Config{KeyData: hostKey, KeyPath: "host.key"})
	if _, err := cli.ClientCert(); err != nil {
		t.Fatalf("certificate with a key from another scope: %v", err)
	}
}

func TestMergeKeepsKeyForCertificateWithUnusableKeyBlock(t *testing.T) {
	cert, key := testCertificatePEM(t, "host")
	_, otherKey := testCertificatePEM(t, "other")
	// The certificate file holds a key for another certificate. The key of
	// the lower scope matches, so it is still used.
	host := &Config{CertData: append(append([]byte(nil), cert...), otherKey...), CertPath: "host.pem"}
	applied := host.Merge(&Config{KeyData: key, KeyPath: "host.key"})
	if _, err := host.ClientCert(); err != nil {
		t.Fatalf("ClientCert() error = %v", err)
	}
	if !slices.Contains(applied, "key") {
		t.Fatalf("applied = %v, want key", applied)
	}
}

func TestMergeKeepsKeyOfTheSameScope(t *testing.T) {
	// One scope sets a combined certificate and also a key. The merge must
	// not drop that scope's key: only a lower scope's key is skipped.
	cert, key := testCertificatePEM(t, "host")
	cli := &Config{}
	section := &Config{CertData: append(append([]byte(nil), cert...), key...), CertPath: "combined.pem", KeyData: key, KeyPath: "host.key"}
	applied := cli.Merge(section)
	if cli.KeyPath != "host.key" || !slices.Contains(applied, "key") {
		t.Fatalf("key = %q, applied = %v; want the section's key", cli.KeyPath, applied)
	}
}

func TestMergeDoesNotReportSkippedKey(t *testing.T) {
	cert, key := testCertificatePEM(t, "host")
	_, globalKey := testCertificatePEM(t, "global")
	host := &Config{CertData: append(append([]byte(nil), cert...), key...), CertPath: "combined.pem"}
	applied := host.Merge(&Config{KeyData: globalKey, KeyPath: "global.key"})
	if slices.Contains(applied, "key") {
		t.Fatalf("applied = %v, want no key", applied)
	}
}

func TestCertHasOwnKey(t *testing.T) {
	cert, key := testCertificatePEM(t, "x")
	_, otherKey := testCertificatePEM(t, "y")
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	for _, test := range []struct {
		name string
		data []byte
		want bool
	}{
		{name: "certificate only", data: cert, want: false},
		{name: "combined", data: join(cert, key), want: true},
		{name: "unrelated key", data: join(cert, otherKey), want: false},
		{name: "encrypted key", data: join(cert, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")), want: false},
		{name: "malformed block before key", data: join([]byte("-----BEGIN X-----\n!!\n-----END X-----\n"), cert, key), want: true},
		{name: "empty", data: nil, want: false},
	} {
		if got := certHasOwnKey(test.data); got != test.want {
			t.Errorf("%s: certHasOwnKey() = %t, want %t", test.name, got, test.want)
		}
	}
}

func TestHostSectionFilesLoadOnlyForTheRequestHost(t *testing.T) {
	dir := t.TempDir()
	cert, key := testCertificatePEM(t, "api")
	certPath := filepath.Join(dir, "api.pem")
	if err := os.WriteFile(certPath, append(cert, key...), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")
	src := "[vpn.corp]\nca-cert = " + missing + "\n\n[api.example.com]\ncert = " + certPath + "\n"

	// A missing file in an unrelated host section does not break parsing.
	f, err := parseFile("config", src)
	if err != nil {
		t.Fatalf("parseFile() error = %v", err)
	}

	api := f.HostConfig("api.example.com")
	if api.CertData != nil {
		t.Fatal("host certificate was read before LoadFiles")
	}
	if err := api.LoadFiles(); err != nil {
		t.Fatalf("LoadFiles() error = %v", err)
	}
	if _, err := api.ClientCert(); err != nil {
		t.Fatalf("ClientCert() error = %v", err)
	}

	// The missing file is reported, with its line, for its own host.
	err = f.HostConfig("vpn.corp").LoadFiles()
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "missing.pem") {
		t.Fatalf("LoadFiles() error = %v, want the missing file at line 2", err)
	}
}

func TestGlobalSectionFilesLoadWhenParsed(t *testing.T) {
	_, err := parseFile("config", "ca-cert = "+filepath.Join(t.TempDir(), "missing.pem")+"\n")
	if err == nil {
		t.Fatal("parseFile() accepted a missing global CA file")
	}
}

func TestLoadFilesRemembersItsResult(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	f, err := parseFile("config", "[*.corp.example]\nkey = "+missing+"\n")
	if err != nil {
		t.Fatal(err)
	}
	host := f.HostConfig("vpn.corp.example")
	if host == nil {
		t.Fatal("wildcard section did not match")
	}
	first := host.LoadFiles()
	if first == nil {
		t.Fatal("LoadFiles() accepted a missing key file")
	}
	// A retry does not report success for a partly loaded section.
	if second := host.LoadFiles(); second == nil || second.Error() != first.Error() {
		t.Fatalf("second LoadFiles() = %v, want %v", second, first)
	}
	var nilConfig *Config
	if err := nilConfig.LoadFiles(); err != nil {
		t.Fatalf("nil LoadFiles() = %v", err)
	}
}

func TestHostSectionStillRejectsUnknownKeysWhenParsed(t *testing.T) {
	if _, err := parseFile("config", "[api.example.com]\nno-such-key = 1\n"); err == nil {
		t.Fatal("parseFile() accepted an unknown key in a host section")
	}
}

func TestHostSectionCACertsKeepTheirOrder(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"first", "second"} {
		cert, _ := testCertificatePEM(t, name)
		path := filepath.Join(dir, name+".pem")
		if err := os.WriteFile(path, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	f, err := parseFile("config", "[api.example.com]\nca-cert = "+paths[0]+"\nca-cert = "+paths[1]+"\n")
	if err != nil {
		t.Fatal(err)
	}
	host := f.HostConfig("api.example.com")
	if err := host.LoadFiles(); err != nil {
		t.Fatal(err)
	}
	if len(host.CACerts) != 2 || host.CACerts[0].Subject.CommonName != "first" || host.CACerts[1].Subject.CommonName != "second" {
		t.Fatalf("CA certificates = %d, want first then second", len(host.CACerts))
	}
}
