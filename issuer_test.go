package caddyest

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func newIssuerFromCaddyfile(t *testing.T, body string) (*Issuer, error) {
	t.Helper()

	issuer := new(Issuer)
	err := issuer.UnmarshalCaddyfile(caddyfile.NewTestDispenser(body))
	return issuer, err
}

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Run("given a full block when parsed then every option is applied", func(t *testing.T) {
		// Given / When
		issuer, err := newIssuerFromCaddyfile(t, `est {
			server https://pki.example.com:8443
			label caddyest
			username robot
			password s3cret
			trusted_ca_file /etc/caddy/est-ca.pem
			client_certificate_file /etc/caddy/est-client.pem
			client_key_file /etc/caddy/est-client-key.pem
			insecure_skip_verify
		}`)

		// Then
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
		}
		if issuer.Server != "https://pki.example.com:8443" {
			t.Errorf("Server = %q", issuer.Server)
		}
		if issuer.Label != "caddyest" {
			t.Errorf("Label = %q", issuer.Label)
		}
		if issuer.Username != "robot" || issuer.Password != "s3cret" {
			t.Errorf("credentials = %q/%q", issuer.Username, issuer.Password)
		}
		if issuer.TrustedCAFile != "/etc/caddy/est-ca.pem" {
			t.Errorf("TrustedCAFile = %q", issuer.TrustedCAFile)
		}
		if issuer.ClientCertificateFile != "/etc/caddy/est-client.pem" {
			t.Errorf("ClientCertificateFile = %q", issuer.ClientCertificateFile)
		}
		if issuer.ClientKeyFile != "/etc/caddy/est-client-key.pem" {
			t.Errorf("ClientKeyFile = %q", issuer.ClientKeyFile)
		}
		if !issuer.InsecureSkipVerify {
			t.Error("InsecureSkipVerify was not set")
		}
	})

	t.Run("given malformed input when parsed then it is rejected", func(t *testing.T) {
		testCases := map[string]string{
			"unknown option":               "est {\n\tnot_an_option value\n}",
			"missing value":                "est {\n\tserver\n}",
			"argument on the issuer name":  "est extra {\n\tserver https://pki.example.com\n}",
			"argument to a boolean option": "est {\n\tinsecure_skip_verify yes\n}",
		}

		for name, body := range testCases {
			t.Run(name, func(t *testing.T) {
				// Given / When
				_, err := newIssuerFromCaddyfile(t, body)

				// Then
				if err == nil {
					t.Fatalf("expected an error for %q", body)
				}
			})
		}
	})
}

func TestValidateRequiresAServer(t *testing.T) {
	testCases := map[string]struct {
		server    string
		wantError bool
	}{
		"configured":      {server: "https://pki.example.com:8443", wantError: false},
		"empty":           {server: "", wantError: true},
		"whitespace only": {server: "   ", wantError: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			// Given
			issuer := &Issuer{Server: testCase.server}

			// When
			err := issuer.Validate()

			// Then
			if testCase.wantError && err == nil {
				t.Fatal("expected an error, got none")
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestIssuerKeySeparatesLabels matters because CertMagic uses this string as a storage
// path: two aliases on one server that collided here would overwrite each other's
// certificates.
func TestIssuerKeySeparatesLabels(t *testing.T) {
	testCases := map[string]struct {
		issuer Issuer
		want   string
	}{
		"no label":   {issuer: Issuer{Server: "https://pki.example.com:8443"}, want: "https://pki.example.com:8443"},
		"with label": {issuer: Issuer{Server: "https://pki.example.com:8443", Label: "tls"}, want: "https://pki.example.com:8443/tls"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			// Given / When
			got := testCase.issuer.IssuerKey()

			// Then
			if got != testCase.want {
				t.Errorf("IssuerKey() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestBuildClientConfig(t *testing.T) {
	t.Run("given only one half of the client key pair then it is rejected", func(t *testing.T) {
		testCases := map[string]Issuer{
			"certificate without key": {Server: "https://pki.example.com", ClientCertificateFile: "cert.pem"},
			"key without certificate": {Server: "https://pki.example.com", ClientKeyFile: "key.pem"},
		}

		for name, issuer := range testCases {
			t.Run(name, func(t *testing.T) {
				// Given / When
				_, err := issuer.buildClientConfig()

				// Then
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				if !strings.Contains(err.Error(), "must be set together") {
					t.Errorf("error %q does not explain the pairing requirement", err)
				}
			})
		}
	})

	t.Run("given a trusted CA file with no certificates then it is rejected", func(t *testing.T) {
		// Given
		path := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatalf("writing file: %v", err)
		}
		issuer := &Issuer{Server: "https://pki.example.com", TrustedCAFile: path}

		// When
		_, err := issuer.buildClientConfig()

		// Then
		if err == nil {
			t.Fatal("expected an error, got none")
		}
		if !strings.Contains(err.Error(), "no PEM certificates") {
			t.Errorf("error %q does not name the cause", err)
		}
	})

	t.Run("given a missing trusted CA file then the error names the file", func(t *testing.T) {
		// Given
		issuer := &Issuer{Server: "https://pki.example.com", TrustedCAFile: "/nonexistent/ca.pem"}

		// When
		_, err := issuer.buildClientConfig()

		// Then
		if err == nil {
			t.Fatal("expected an error, got none")
		}
		if !strings.Contains(err.Error(), "trusted CA file") {
			t.Errorf("error %q does not say which file failed", err)
		}
	})
}

// TestChooseOperation covers the decision that used to be tracked in memory and so did not
// survive a restart: whether this issuance is a first enrolment or a renewal.
func TestChooseOperation(t *testing.T) {
	csr := newTestCSR("www.example.com", "www.example.com")

	t.Run("given no certificate is held then it enrolls", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)

		// When
		operation, identity := issuer.chooseOperation(context.Background(), csr)

		// Then
		if operation != operationEnroll {
			t.Errorf("operation = %q, want %q", operation, operationEnroll)
		}
		if identity != nil {
			t.Error("an identity was chosen for a first enrolment")
		}
	})

	t.Run("given the certificate is held then it re-enrolls with it", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		seedStorage(t, issuer.storage, issuer.IssuerKey(), storageNamesKey(csr), "www.example.com")

		// When
		operation, identity := issuer.chooseOperation(context.Background(), csr)

		// Then
		if operation != operationReenroll {
			t.Errorf("operation = %q, want %q", operation, operationReenroll)
		}
		if identity == nil {
			t.Fatal("re-enrolment was chosen with no certificate to authenticate it")
		}
		if identity.Leaf.Subject.CommonName != "www.example.com" {
			t.Errorf("identity = %q, want the certificate being replaced", identity.Leaf.Subject.CommonName)
		}
	})

	t.Run("given a different name set is held then it enrolls", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		other := newTestCSR("other.example.com", "other.example.com")
		seedStorage(t, issuer.storage, issuer.IssuerKey(), storageNamesKey(other), "other.example.com")

		// When
		operation, _ := issuer.chooseOperation(context.Background(), csr)

		// Then
		if operation != operationEnroll {
			t.Errorf("operation = %q, want %q", operation, operationEnroll)
		}
	})

	// Losing the certificate to a storage failure must not leave Caddy with none at all.
	t.Run("given the stored certificate is unreadable then it enrolls", func(t *testing.T) {
		// Given
		issuer := newStorageIssuer(t)
		key := certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), storageNamesKey(csr))
		if err := issuer.storage.Store(context.Background(), key, []byte("not a certificate")); err != nil {
			t.Fatalf("storing certificate: %v", err)
		}

		// When
		operation, identity := issuer.chooseOperation(context.Background(), csr)

		// Then
		if operation != operationEnroll {
			t.Errorf("operation = %q, want %q", operation, operationEnroll)
		}
		if identity != nil {
			t.Error("an unreadable certificate was offered as an identity")
		}
	})
}

func TestEnroll(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "www.example.com"},
		Raw:     []byte{0x30, 0x00},
	}

	root := newRootAuthority(t, "Enroll Root CA")
	intermediate := root.issueAuthority(t, "Enroll Issuing CA")
	leaf := intermediate.issueLeaf(t, "www.example.com")

	t.Run("given a full chain from the server then it is rendered leaf first", func(t *testing.T) {
		// Given
		issuer := &Issuer{logger: zap.NewNop()}
		var receivedCSR []byte
		call := func(_ context.Context, csrDER []byte) ([]*x509.Certificate, error) {
			receivedCSR = csrDER
			return []*x509.Certificate{leaf, intermediate.certificate, root.certificate}, nil
		}

		// When
		issued, err := issuer.enroll(context.Background(), csr, call, operationEnroll)

		// Then
		if err != nil {
			t.Fatalf("enroll returned error: %v", err)
		}
		if string(receivedCSR) != string(csr.Raw) {
			t.Errorf("the DER CSR was not passed through: %q", receivedCSR)
		}
		if got, want := decodedCommonNames(t, issued.Certificate), []string{"www.example.com", "Enroll Issuing CA"}; !equalStrings(got, want) {
			t.Errorf("served chain = %v, want %v", got, want)
		}
	})

	// The gap this closes: an EST server may answer /simpleenroll with the leaf alone, and
	// a TLS server presenting only a leaf gives clients no path to a trusted root.
	t.Run("given a leaf-only response then the chain is completed from cacerts", func(t *testing.T) {
		// Given
		fetches := 0
		issuer := &Issuer{logger: zap.NewNop(), caChain: new(caChainCache)}
		issuer.fetchCACerts = func(context.Context) ([]*x509.Certificate, error) {
			fetches++
			return []*x509.Certificate{root.certificate, intermediate.certificate}, nil
		}
		call := func(context.Context, []byte) ([]*x509.Certificate, error) {
			return []*x509.Certificate{leaf}, nil
		}

		// When: twice, because the CA chain must be fetched once and then reused.
		first, err := issuer.enroll(context.Background(), csr, call, operationEnroll)
		if err != nil {
			t.Fatalf("enroll returned error: %v", err)
		}
		if _, err := issuer.enroll(context.Background(), csr, call, operationReenroll); err != nil {
			t.Fatalf("second enroll returned error: %v", err)
		}

		// Then
		if got, want := decodedCommonNames(t, first.Certificate), []string{"www.example.com", "Enroll Issuing CA"}; !equalStrings(got, want) {
			t.Errorf("served chain = %v, want %v", got, want)
		}
		if fetches != 1 {
			t.Errorf("cacerts was fetched %d times, want 1", fetches)
		}
	})

	// Refusing the certificate would be worse than serving a short chain: the leaf still
	// works for clients that already hold the issuing CA.
	t.Run("given cacerts is unreachable then the leaf is still issued", func(t *testing.T) {
		// Given
		issuer := &Issuer{logger: zap.NewNop(), caChain: new(caChainCache)}
		issuer.fetchCACerts = func(context.Context) ([]*x509.Certificate, error) {
			return nil, errors.New("est: cacerts failed with status 503")
		}
		call := func(context.Context, []byte) ([]*x509.Certificate, error) {
			return []*x509.Certificate{leaf}, nil
		}

		// When
		issued, err := issuer.enroll(context.Background(), csr, call, operationEnroll)

		// Then
		if err != nil {
			t.Fatalf("enroll returned error: %v", err)
		}
		if got, want := decodedCommonNames(t, issued.Certificate), []string{"www.example.com"}; !equalStrings(got, want) {
			t.Errorf("served chain = %v, want %v", got, want)
		}
	})

	t.Run("given the server refuses then the error propagates", func(t *testing.T) {
		// Given
		issuer := &Issuer{logger: zap.NewNop()}
		refusal := errors.New("est: simpleenroll failed with status 401")
		call := func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, refusal }

		// When
		_, err := issuer.enroll(context.Background(), csr, call, operationEnroll)

		// Then
		if !errors.Is(err, refusal) {
			t.Fatalf("error %v does not wrap the server refusal", err)
		}
	})
}

func TestIssueRejectsAMissingRequest(t *testing.T) {
	// Given
	issuer := &Issuer{logger: zap.NewNop()}

	// When
	_, err := issuer.Issue(context.Background(), nil)

	// Then
	if err == nil {
		t.Fatal("expected an error, got none")
	}
}

func decodePEMBlocks(t *testing.T, encoded []byte) []*pem.Block {
	t.Helper()

	var blocks []*pem.Block
	rest := encoded
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return blocks
		}
		blocks = append(blocks, block)
		rest = remaining
	}
}

func decodedCommonNames(t *testing.T, encoded []byte) []string {
	t.Helper()

	var certificates []*x509.Certificate
	for _, block := range decodePEMBlocks(t, encoded) {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing served certificate: %v", err)
		}
		certificates = append(certificates, certificate)
	}
	return commonNames(certificates)
}
