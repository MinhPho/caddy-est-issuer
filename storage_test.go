package caddyest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func newTestCSR(commonName string, dnsNames ...string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}
}

// seedStorage writes a certificate and its key where CertMagic would, so the issuer has to
// find them at the same keys CertMagic itself uses.
func seedStorage(t *testing.T, storage certmagic.Storage, issuerKey, namesKey, commonName string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}

	ctx := context.Background()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, namesKey), certPEM); err != nil {
		t.Fatalf("storing certificate: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, namesKey), keyPEM); err != nil {
		t.Fatalf("storing private key: %v", err)
	}
}

func newStorageIssuer(t *testing.T) *Issuer {
	t.Helper()

	issuer := &Issuer{Server: "https://pki.example.com:8443", logger: zap.NewNop()}
	issuer.SetConfig(&certmagic.Config{Storage: &certmagic.FileStorage{Path: t.TempDir()}})
	return issuer
}

// TestStorageNamesKeyMatchesCertMagic is the pin on a coupling this package cannot avoid:
// the names key is built from an unexported CertMagic helper, so the derivation is
// replicated here and checked against the exported half of the same layout.
func TestStorageNamesKeyMatchesCertMagic(t *testing.T) {
	testCases := map[string]struct {
		csr  *x509.CertificateRequest
		sans []string
	}{
		"common name only": {
			csr:  newTestCSR("www.example.com"),
			sans: []string{"www.example.com"},
		},
		"common name and SANs": {
			csr:  newTestCSR("www.example.com", "www.example.com", "example.com"),
			sans: []string{"www.example.com", "www.example.com", "example.com"},
		},
		"IP address": {
			csr: &x509.CertificateRequest{
				Subject:     pkix.Name{CommonName: "www.example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			sans: []string{"www.example.com", "192.0.2.1"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			// Given
			resource := certmagic.CertificateResource{SANs: testCase.sans}

			// When
			got := storageNamesKey(testCase.csr)

			// Then
			if want := resource.NamesKey(); got != want {
				t.Errorf("storageNamesKey() = %q, want %q", got, want)
			}
		})
	}
}

// TestStorageNamesKeyIsOrderIndependent guards the renewal decision: a CSR listing the same
// names in a different order is the same certificate and must resolve to the same key.
func TestStorageNamesKeyIsOrderIndependent(t *testing.T) {
	// Given
	first := newTestCSR("www.example.com", "www.example.com", "example.com")
	second := newTestCSR("www.example.com", "example.com", "www.example.com")
	different := newTestCSR("www.example.com", "www.example.com")

	// When / Then
	if storageNamesKey(first) != storageNamesKey(second) {
		t.Errorf("reordered SANs produced different keys: %q vs %q", storageNamesKey(first), storageNamesKey(second))
	}
	if storageNamesKey(first) == storageNamesKey(different) {
		t.Error("a different name set produced the same key")
	}
}

func TestFindCurrentCertificate(t *testing.T) {
	csr := newTestCSR("www.example.com", "www.example.com")

	t.Run("given storage holds no certificate for the names then none is found", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)

		// When
		current, err := issuer.findCurrentCertificate(context.Background(), csr)

		// Then
		if err != nil {
			t.Fatalf("findCurrentCertificate returned error: %v", err)
		}
		if current != nil {
			t.Error("a certificate was found in empty storage")
		}
	})

	t.Run("given storage holds the certificate then it is returned with its key", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		seedStorage(t, issuer.storage, issuer.IssuerKey(), storageNamesKey(csr), "www.example.com")

		// When
		current, err := issuer.findCurrentCertificate(context.Background(), csr)

		// Then
		if err != nil {
			t.Fatalf("findCurrentCertificate returned error: %v", err)
		}
		if current == nil {
			t.Fatal("the stored certificate was not found")
		}
		if current.PrivateKey == nil {
			t.Error("the certificate was returned without its private key")
		}
		if current.Leaf == nil || current.Leaf.Subject.CommonName != "www.example.com" {
			t.Errorf("leaf = %v, want a certificate for www.example.com", current.Leaf)
		}
	})

	// A certificate issued by a different issuer lives under a different storage prefix, so
	// switching a site from ACME to EST must enrol rather than try to renew.
	t.Run("given the certificate belongs to another issuer then none is found", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		seedStorage(t, issuer.storage, "acme-v02.api.letsencrypt.org-directory", storageNamesKey(csr), "www.example.com")

		// When
		current, err := issuer.findCurrentCertificate(context.Background(), csr)

		// Then
		if err != nil {
			t.Fatalf("findCurrentCertificate returned error: %v", err)
		}
		if current != nil {
			t.Error("another issuer's certificate was treated as this issuer's")
		}
	})

	t.Run("given a certificate with no matching key then the error says so", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		key := certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), storageNamesKey(csr))
		if err := issuer.storage.Store(context.Background(), key, []byte("not a certificate")); err != nil {
			t.Fatalf("storing certificate: %v", err)
		}

		// When
		_, err := issuer.findCurrentCertificate(context.Background(), csr)

		// Then
		if err == nil {
			t.Fatal("expected an error, got none")
		}
	})

	t.Run("given no storage is configured then none is found", func(t *testing.T) {
		// Given
		issuer := &Issuer{Server: "https://pki.example.com:8443", logger: zap.NewNop()}

		// When
		current, err := issuer.findCurrentCertificate(context.Background(), csr)

		// Then
		if err != nil {
			t.Fatalf("findCurrentCertificate returned error: %v", err)
		}
		if current != nil {
			t.Error("a certificate was found with no storage to read")
		}
	})
}
