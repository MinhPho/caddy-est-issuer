//go:build integration

// These tests drive the issuer end to end against a live EST server, which is the only way
// to prove the renewal path: a re-enrolment is authenticated by the certificate it
// replaces, so nothing short of a real handshake shows that the right one was presented.
//
// Start a server with "make lab" and run them with "make test-integration".
package caddyest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/MinhPho/caddy-est-issuer/internal/estclient"
)

const defaultLabServer = "https://127.0.0.1:8443"

func labServer() string {
	if server := os.Getenv("EST_LAB_SERVER"); server != "" {
		return server
	}
	return defaultLabServer
}

// writeLabTrustFile learns the lab CA the way an operator does before the first enrolment:
// over an unauthenticated /cacerts, verified out of band.
func writeLabTrustFile(t *testing.T) string {
	t.Helper()

	bootstrap, err := estclient.New(estclient.Config{Server: labServer(), InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("constructing bootstrap client: %v", err)
	}
	caCerts, err := bootstrap.CACerts(context.Background())
	if err != nil {
		t.Fatalf("CACerts against %s failed: %v", labServer(), err)
	}

	var bundle []byte
	for _, certificate := range caCerts {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})...)
	}
	path := filepath.Join(t.TempDir(), "lab-ca.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("writing trust file: %v", err)
	}
	return path
}

// newLabIssuer wires an Issuer the way Provision does, minus the caddy.Context a test
// cannot supply.
func newLabIssuer(t *testing.T, storage certmagic.Storage) *Issuer {
	t.Helper()

	issuer := &Issuer{
		Server:        labServer(),
		TrustedCAFile: writeLabTrustFile(t),
		logger:        zap.NewNop(),
		storage:       storage,
		caChain:       new(caChainCache),
	}

	config, err := issuer.buildClientConfig()
	if err != nil {
		t.Fatalf("building client config: %v", err)
	}
	client, err := estclient.New(config)
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}
	issuer.client = client
	issuer.fetchCACerts = client.CACerts
	return issuer
}

func newLabCSR(t *testing.T, commonName string) (*x509.CertificateRequest, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName},
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return csr, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// storeIssued files a certificate where CertMagic files it after Issue returns, which is
// what makes the next issuance for those names a renewal.
func storeIssued(t *testing.T, issuer *Issuer, csr *x509.CertificateRequest, certificatePEM, keyPEM []byte) {
	t.Helper()

	ctx := context.Background()
	namesKey := storageNamesKey(csr)
	if err := issuer.storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), namesKey), certificatePEM); err != nil {
		t.Fatalf("storing certificate: %v", err)
	}
	if err := issuer.storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuer.IssuerKey(), namesKey), keyPEM); err != nil {
		t.Fatalf("storing private key: %v", err)
	}
}

func leafOf(t *testing.T, certificatePEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("issued certificate was not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	return leaf
}

// TestGivenAStoredCertificateWhenIssuingThenTheLiveServerAcceptsTheRenewal is the test the
// per-process enrolment history could not support: the issuer that renews holds no memory
// of the one that enrolled, exactly as it would after a restart.
func TestGivenAStoredCertificateWhenIssuingThenTheLiveServerAcceptsTheRenewal(t *testing.T) {
	ctx := context.Background()
	storage := &certmagic.FileStorage{Path: t.TempDir()}

	// Given: a first enrolment, filed where CertMagic would file it.
	enrolling := newLabIssuer(t, storage)
	csr, keyPEM := newLabCSR(t, "caddy-est-issuer-renewal.example.com")

	issued, err := enrolling.Issue(ctx, csr)
	if err != nil {
		t.Fatalf("first Issue failed: %v", err)
	}
	storeIssued(t, enrolling, csr, issued.Certificate, keyPEM)
	first := leafOf(t, issued.Certificate)

	// When: a new issuer, with nothing in memory, is asked for the same names again.
	renewing := newLabIssuer(t, storage)
	if operation, _ := renewing.chooseOperation(ctx, csr); operation != operationReenroll {
		t.Fatalf("operation = %q, want %q", operation, operationReenroll)
	}
	renewed, err := renewing.Issue(ctx, csr)

	// Then: the server accepted it, which it only does for a request authenticated by the
	// certificate being replaced, and a different certificate came back.
	if err != nil {
		t.Fatalf("renewal Issue failed: %v", err)
	}
	second := leafOf(t, renewed.Certificate)
	if second.Subject.CommonName != first.Subject.CommonName {
		t.Errorf("renewed CN = %q, want %q", second.Subject.CommonName, first.Subject.CommonName)
	}
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("the renewal returned the same serial number, so no new certificate was issued")
	}
}

// TestGivenEmptyStorageWhenIssuingThenTheLiveServerEnrolls is the other half: with nothing
// stored there is no identity to renew with, and enrolment is the only call that can work.
func TestGivenEmptyStorageWhenIssuingThenTheLiveServerEnrolls(t *testing.T) {
	ctx := context.Background()

	// Given
	issuer := newLabIssuer(t, &certmagic.FileStorage{Path: t.TempDir()})
	csr, _ := newLabCSR(t, "caddy-est-issuer-bootstrap.example.com")

	// When
	operation, identity := issuer.chooseOperation(ctx, csr)
	issued, err := issuer.Issue(ctx, csr)

	// Then
	if operation != operationEnroll || identity != nil {
		t.Errorf("operation = %q with identity %v, want a plain enrolment", operation, identity)
	}
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if got := leafOf(t, issued.Certificate).Subject.CommonName; got != "caddy-est-issuer-bootstrap.example.com" {
		t.Errorf("leaf CN = %q, want the requested name", got)
	}
}
