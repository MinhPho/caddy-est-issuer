//go:build integration

// These tests run the full EST lifecycle against a live server rather than a stub, so
// they catch the things a handwritten test double cannot: real TLS, real base64 framing,
// and a real degenerate PKCS#7 produced by someone else's encoder.
//
// Start a server with "make lab" and run them with "make test-integration".
package estclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
)

const defaultLabServer = "https://127.0.0.1:8443"

func labServer() string {
	if server := os.Getenv("EST_LAB_SERVER"); server != "" {
		return server
	}
	return defaultLabServer
}

func newCSR(t *testing.T, commonName string) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
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
	return csr, key
}

// TestGivenLiveESTServerWhenEnrollingThenCertificateIsIssuedAndRenewable walks the whole
// bootstrap sequence an unprovisioned TLS server performs: learn the CA out of band,
// enrol against it, then renew using the certificate just issued.
func TestGivenLiveESTServerWhenEnrollingThenCertificateIsIssuedAndRenewable(t *testing.T) {
	ctx := context.Background()

	// Given: the CA chain fetched without a trust anchor, which is the only step RFC 7030
	// allows to be unauthenticated, and which the operator is expected to verify manually.
	bootstrap, err := New(Config{Server: labServer(), InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("constructing bootstrap client: %v", err)
	}
	caCerts, err := bootstrap.CACerts(ctx)
	if err != nil {
		t.Fatalf("CACerts against %s failed: %v", labServer(), err)
	}
	if len(caCerts) == 0 {
		t.Fatal("CACerts returned no certificates")
	}

	trust := x509.NewCertPool()
	for _, certificate := range caCerts {
		trust.AddCert(certificate)
	}

	// When: enrolling a fresh key, now verifying the server against that chain.
	client, err := New(Config{Server: labServer(), RootCAs: trust})
	if err != nil {
		t.Fatalf("constructing verified client: %v", err)
	}
	csr, key := newCSR(t, "caddy-est-integration.example.com")

	issued, err := client.Enroll(ctx, csr.Raw)
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// Then: a usable leaf comes back, carrying the name that was requested.
	if len(issued) == 0 {
		t.Fatal("Enroll returned no certificates")
	}
	leaf := issued[0]
	if leaf.Subject.CommonName != "caddy-est-integration.example.com" {
		t.Errorf("leaf CN = %q, want the requested name", leaf.Subject.CommonName)
	}
	if err := leaf.CheckSignatureFrom(caCerts[0]); err != nil {
		t.Logf("leaf is not signed directly by the first CA cert, which is expected with an intermediate: %v", err)
	}

	// When: renewing on the same client that just enrolled, authenticated by the
	// certificate that enrolment returned. That is the real sequence, and it proves the
	// per-call identity reaches a live server's handshake rather than only a test double.
	// The presented chain must reach a CA the server trusts, and /simpleenroll returns
	// only the leaf here, so the issuing chain from /cacerts is appended.
	chain := make([][]byte, 0, len(issued)+len(caCerts))
	for _, certificate := range issued {
		chain = append(chain, certificate.Raw)
	}
	for _, certificate := range caCerts {
		if certificate.Equal(leaf) {
			continue
		}
		chain = append(chain, certificate.Raw)
	}
	renewed, err := client.Reenroll(ctx, csr.Raw, &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        leaf,
	})

	// Then: a second certificate is issued for the same name.
	if err != nil {
		t.Fatalf("Reenroll failed: %v", err)
	}
	if len(renewed) == 0 {
		t.Fatal("Reenroll returned no certificates")
	}
	if renewed[0].Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("renewed CN = %q, want %q", renewed[0].Subject.CommonName, leaf.Subject.CommonName)
	}
	if renewed[0].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Error("reenrollment returned the same serial number, so no new certificate was issued")
	}
}

// TestGivenLiveESTServerWhenReenrollingWithoutClientCertificateThenServerRefuses pins the
// authentication rule the issuer depends on: a renewal must present the certificate it is
// replacing.
func TestGivenLiveESTServerWhenReenrollingWithoutClientCertificateThenServerRefuses(t *testing.T) {
	ctx := context.Background()

	// Given: a client that verifies the server but presents no certificate of its own.
	bootstrap, err := New(Config{Server: labServer(), InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("constructing bootstrap client: %v", err)
	}
	caCerts, err := bootstrap.CACerts(ctx)
	if err != nil {
		t.Fatalf("CACerts against %s failed: %v", labServer(), err)
	}
	trust := x509.NewCertPool()
	for _, certificate := range caCerts {
		trust.AddCert(certificate)
	}
	client, err := New(Config{Server: labServer(), RootCAs: trust})
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}
	csr, _ := newCSR(t, "caddy-est-unauthenticated.example.com")

	// When: asking to renew anyway.
	_, err = client.Reenroll(ctx, csr.Raw, nil)

	// Then: the server refuses, and the client surfaces it rather than panicking.
	if err == nil {
		t.Fatal("expected the server to refuse an unauthenticated reenrollment")
	}
	t.Logf("server refused as expected: %v", err)
}
