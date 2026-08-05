package caddyest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// --- certificate hierarchy helpers -------------------------------------------------

type testAuthority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func newRootAuthority(t *testing.T, commonName string) testAuthority {
	t.Helper()
	return signAuthority(t, commonName, nil)
}

func (ca testAuthority) issueAuthority(t *testing.T, commonName string) testAuthority {
	t.Helper()
	return signAuthority(t, commonName, &ca)
}

func signAuthority(t *testing.T, commonName string, parent *testAuthority) testAuthority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serialFor(commonName)),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.certificate, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return testAuthority{certificate: certificate, key: key}
}

func (ca testAuthority) issueLeaf(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialFor(commonName)),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating leaf: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return certificate
}

func serialFor(commonName string) int64 {
	var serial int64
	for _, r := range commonName {
		serial = serial*31 + int64(r)
	}
	if serial < 0 {
		serial = -serial
	}
	return serial + 1
}

func commonNames(certificates []*x509.Certificate) []string {
	names := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		names = append(names, certificate.Subject.CommonName)
	}
	return names
}

// TestBuildPresentedChain covers the gap that made Caddy serve a leaf-only chain: an EST
// server is allowed to return just the issued certificate, but a TLS server that presents
// only a leaf gives clients no way to build a path to a trusted root.
func TestBuildPresentedChain(t *testing.T) {
	root := newRootAuthority(t, "Test Root CA")
	intermediate := root.issueAuthority(t, "Test Issuing CA")
	leaf := intermediate.issueLeaf(t, "www.example.com")

	t.Run("given a leaf-only enrolment then intermediates come from the CA chain", func(t *testing.T) {
		// Given: what /simpleenroll returned, and what /cacerts offers.
		issued := []*x509.Certificate{leaf}
		caCerts := []*x509.Certificate{root.certificate, intermediate.certificate}

		// When
		chain, rooted := buildPresentedChain(issued, caCerts)

		// Then: leaf first, intermediate next, and the root left out.
		if !rooted {
			t.Error("chain should reach a self-signed root")
		}
		if got, want := commonNames(chain), []string{"www.example.com", "Test Issuing CA"}; !equalStrings(got, want) {
			t.Errorf("chain = %v, want %v", got, want)
		}
	})

	t.Run("given the server already returned the chain then it is not duplicated", func(t *testing.T) {
		// Given
		issued := []*x509.Certificate{leaf, intermediate.certificate}
		caCerts := []*x509.Certificate{root.certificate, intermediate.certificate}

		// When
		chain, rooted := buildPresentedChain(issued, caCerts)

		// Then
		if !rooted {
			t.Error("chain should reach a self-signed root")
		}
		if got, want := commonNames(chain), []string{"www.example.com", "Test Issuing CA"}; !equalStrings(got, want) {
			t.Errorf("chain = %v, want %v", got, want)
		}
	})

	t.Run("given the issuer is unavailable then the leaf is served alone and reported", func(t *testing.T) {
		// Given: a CA set that cannot link the leaf to anything.
		unrelated := newRootAuthority(t, "Unrelated CA")

		// When
		chain, rooted := buildPresentedChain([]*x509.Certificate{leaf}, []*x509.Certificate{unrelated.certificate})

		// Then: issuance still succeeds, but the caller can tell the chain is incomplete.
		if rooted {
			t.Error("an unlinkable leaf must not be reported as rooted")
		}
		if got, want := commonNames(chain), []string{"www.example.com"}; !equalStrings(got, want) {
			t.Errorf("chain = %v, want %v", got, want)
		}
	})

	t.Run("given a self-signed leaf then it is served as-is", func(t *testing.T) {
		// Given
		selfSigned := newRootAuthority(t, "Self Signed Server")

		// When
		chain, rooted := buildPresentedChain([]*x509.Certificate{selfSigned.certificate}, nil)

		// Then
		if !rooted {
			t.Error("a self-signed certificate is its own root")
		}
		if len(chain) != 1 {
			t.Errorf("chain = %v, want the certificate alone", commonNames(chain))
		}
	})

	t.Run("given a deeper hierarchy in arbitrary order then the path is still ordered", func(t *testing.T) {
		// Given: two intermediates, supplied to the builder out of order.
		second := intermediate.issueAuthority(t, "Test Sub Issuing CA")
		deepLeaf := second.issueLeaf(t, "deep.example.com")
		caCerts := []*x509.Certificate{second.certificate, root.certificate, intermediate.certificate}

		// When
		chain, rooted := buildPresentedChain([]*x509.Certificate{deepLeaf}, caCerts)

		// Then
		if !rooted {
			t.Error("chain should reach a self-signed root")
		}
		want := []string{"deep.example.com", "Test Sub Issuing CA", "Test Issuing CA"}
		if got := commonNames(chain); !equalStrings(got, want) {
			t.Errorf("chain = %v, want %v", got, want)
		}
	})

	t.Run("given no certificates then nothing is presented", func(t *testing.T) {
		// Given / When
		chain, rooted := buildPresentedChain(nil, nil)

		// Then
		if len(chain) != 0 || rooted {
			t.Errorf("chain = %v, rooted = %v, want empty and false", commonNames(chain), rooted)
		}
	})
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
