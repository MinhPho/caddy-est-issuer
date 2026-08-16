package estclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// newSelfSignedCertificate builds a throwaway certificate for use as EST response
// payload. Generating it in-test keeps the repository free of fixture certificates that
// silently expire.
func newSelfSignedCertificate(t *testing.T, commonName string) *x509.Certificate {
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
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return certificate
}

// encodeCertsOnlyResponse renders certificates the way an EST server does: a degenerate
// PKCS#7 structure, base64 encoded.
func encodeCertsOnlyResponse(t *testing.T, certificates ...*x509.Certificate) []byte {
	t.Helper()

	var der []byte
	for _, certificate := range certificates {
		der = append(der, certificate.Raw...)
	}
	degenerate, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatalf("building degenerate PKCS#7: %v", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(degenerate)))
	base64.StdEncoding.Encode(encoded, degenerate)
	return encoded
}

// newClientIdentity builds a self-signed key pair for use as a TLS client certificate,
// which is what a re-enrolment authenticates with.
func newClientIdentity(t *testing.T, commonName string) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTestClient starts a TLS test server with the given handler and returns a Client that
// trusts it, so tests exercise the real TLS path rather than skipping verification.
func newTestClient(t *testing.T, cfg Config, handler http.Handler) *Client {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	cfg.Server = server.URL
	cfg.RootCAs = pool

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}
	return client
}

func TestNewRejectsUnusableConfig(t *testing.T) {
	testCases := map[string]struct {
		server    string
		wantError string
	}{
		"empty server":      {server: "", wantError: "server URL is required"},
		"plaintext http":    {server: "http://pki.example.com", wantError: "must use https"},
		"unparseable URL":   {server: "https://pki.example.com:not-a-port", wantError: "not a valid URL"},
		"scheme-less value": {server: "pki.example.com", wantError: "must use https"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{Server: testCase.server})

			if err == nil {
				t.Fatalf("expected an error for server %q, got none", testCase.server)
			}
			if !strings.Contains(err.Error(), testCase.wantError) {
				t.Errorf("error %q does not mention %q", err, testCase.wantError)
			}
		})
	}
}

func TestEndpointBuildsWellKnownPath(t *testing.T) {
	testCases := map[string]struct {
		server    string
		label     string
		operation string
		want      string
	}{
		"no label": {
			server: "https://pki.example.com:8443", label: "", operation: operationCACerts,
			want: "https://pki.example.com:8443/.well-known/est/cacerts",
		},
		"with label": {
			server: "https://pki.example.com:8443", label: "caddyest", operation: operationSimpleEnroll,
			want: "https://pki.example.com:8443/.well-known/est/caddyest/simpleenroll",
		},
		"label with stray slashes": {
			server: "https://pki.example.com:8443", label: "/caddyest/", operation: operationCACerts,
			want: "https://pki.example.com:8443/.well-known/est/caddyest/cacerts",
		},
		"server with trailing slash": {
			server: "https://pki.example.com:8443/", label: "", operation: operationCACerts,
			want: "https://pki.example.com:8443/.well-known/est/cacerts",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			client, err := New(Config{Server: testCase.server, Label: testCase.label})
			if err != nil {
				t.Fatalf("constructing client: %v", err)
			}

			got := client.endpoint(testCase.operation)

			if got != testCase.want {
				t.Errorf("endpoint = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestCACertsReturnsServerChain(t *testing.T) {
	expected := newSelfSignedCertificate(t, "Lab Issuing CA")
	var requestedPath string

	client := newTestClient(t, Config{Label: "caddyest"}, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestedPath = r.URL.Path
			w.Header().Set("Content-Type", mimeTypePKCS7)
			w.Header().Set(headerContentTransferEncoding, encodingBase64)
			_, _ = w.Write(encodeCertsOnlyResponse(t, expected))
		}))

	certificates, err := client.CACerts(context.Background())

	if err != nil {
		t.Fatalf("CACerts returned error: %v", err)
	}
	if requestedPath != "/.well-known/est/caddyest/cacerts" {
		t.Errorf("requested path = %q", requestedPath)
	}
	if len(certificates) != 1 || certificates[0].Subject.CommonName != "Lab Issuing CA" {
		t.Errorf("unexpected certificates: %+v", certificates)
	}
}

func TestEnrollSendsBase64CSRAndBasicAuth(t *testing.T) {
	issued := newSelfSignedCertificate(t, "server.example.com")
	csrDER := []byte{0x30, 0x82, 0x01, 0x02, 0x03}

	var (
		gotContentType string
		gotEncoding    string
		gotBody        string
		gotUser        string
		gotPassword    string
		gotMethod      string
	)

	client := newTestClient(t, Config{Username: "robot", Password: "secret"}, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotContentType = r.Header.Get("Content-Type")
			gotEncoding = r.Header.Get(headerContentTransferEncoding)
			gotUser, gotPassword, _ = r.BasicAuth()
			raw, _ := io.ReadAll(r.Body)
			gotBody = string(raw)

			w.Header().Set("Content-Type", mimeTypePKCS7)
			_, _ = w.Write(encodeCertsOnlyResponse(t, issued))
		}))

	certificates, err := client.Enroll(context.Background(), csrDER)

	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != mimeTypePKCS10 {
		t.Errorf("Content-Type = %q, want %q", gotContentType, mimeTypePKCS10)
	}
	if gotEncoding != encodingBase64 {
		t.Errorf("Content-Transfer-Encoding = %q, want %q", gotEncoding, encodingBase64)
	}
	if want := base64.StdEncoding.EncodeToString(csrDER); strings.TrimSpace(gotBody) != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
	if gotUser != "robot" || gotPassword != "secret" {
		t.Errorf("basic auth = %q/%q, want robot/secret", gotUser, gotPassword)
	}
	if len(certificates) != 1 || certificates[0].Subject.CommonName != "server.example.com" {
		t.Errorf("unexpected certificates: %+v", certificates)
	}
}

// TestEnrollWrapsTheBase64BodyAsMIMELines pins the framing RFC 7030 section 4.2.1 requires:
// the base64 of RFC 2045, whose lines are at most 76 characters and end in CRLF. Cisco's
// libest rejects a single unbroken line as a corrupt PKCS#10, and it is the reference the
// widest range of servers descends from.
func TestEnrollWrapsTheBase64BodyAsMIMELines(t *testing.T) {
	issued := newSelfSignedCertificate(t, "server.example.com")
	csrDER := bytes.Repeat([]byte{0x30, 0x82, 0x01, 0x02}, 100)

	var gotBody string
	client := newTestClient(t, Config{}, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			gotBody = string(raw)
			w.Header().Set("Content-Type", mimeTypePKCS7)
			_, _ = w.Write(encodeCertsOnlyResponse(t, issued))
		}))

	if _, err := client.Enroll(context.Background(), csrDER); err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(gotBody, "\r\n"), "\r\n")
	if len(lines) < 2 {
		t.Fatalf("body was not split into CRLF lines: %q", gotBody)
	}
	for index, line := range lines {
		if len(line) > 76 || strings.ContainsAny(line, "\r\n") {
			t.Errorf("line %d is %d characters, want at most 76 with no bare line breaks", index, len(line))
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		t.Fatalf("body did not decode as base64 once unwrapped: %v", err)
	}
	if !bytes.Equal(decoded, csrDER) {
		t.Error("unwrapped body did not decode to the CSR that was sent")
	}
}

func TestEnrollSurfacesServerRejectionAsProtocolError(t *testing.T) {
	client := newTestClient(t, Config{}, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("client certificate required"))
		}))

	_, err := client.Enroll(context.Background(), []byte{0x30, 0x00})

	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) {
		t.Fatalf("expected a *ProtocolError, got %T: %v", err, err)
	}
	if protocolError.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", protocolError.StatusCode)
	}
	if !strings.Contains(protocolError.Detail, "client certificate required") {
		t.Errorf("detail %q lost the server message", protocolError.Detail)
	}
	if !strings.Contains(protocolError.Error(), operationSimpleEnroll) {
		t.Errorf("error %q does not name the operation", protocolError)
	}
}

func TestParseCertsOnlyPKCS7AcceptsServerVariations(t *testing.T) {
	certificate := newSelfSignedCertificate(t, "Variation CA")
	canonical := encodeCertsOnlyResponse(t, certificate)

	withLineBreaks := insertLineBreaks(string(canonical), 64)
	withPEMArmour := "-----BEGIN PKCS7-----\n" + withLineBreaks + "\n-----END PKCS7-----\n"

	testCases := map[string]string{
		"single line base64": string(canonical),
		"wrapped at 64":      withLineBreaks,
		"PEM armoured":       withPEMArmour,
		"trailing newline":   string(canonical) + "\n",
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			certificates, err := ParseCertsOnlyPKCS7([]byte(body))

			if err != nil {
				t.Fatalf("ParseCertsOnlyPKCS7 returned error: %v", err)
			}
			if len(certificates) != 1 || certificates[0].Subject.CommonName != "Variation CA" {
				t.Errorf("unexpected certificates: %+v", certificates)
			}
		})
	}
}

func TestParseCertsOnlyPKCS7RejectsBadInput(t *testing.T) {
	testCases := map[string]struct {
		body      string
		wantError string
	}{
		"empty":             {body: "   ", wantError: "empty response body"},
		"not base64":        {body: "!!!! not base64 !!!!", wantError: "decoding base64"},
		"base64 but not p7": {body: base64.StdEncoding.EncodeToString([]byte("hello")), wantError: "parsing PKCS#7"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCertsOnlyPKCS7([]byte(testCase.body))

			if err == nil {
				t.Fatalf("expected an error, got none")
			}
			if !strings.Contains(err.Error(), testCase.wantError) {
				t.Errorf("error %q does not mention %q", err, testCase.wantError)
			}
		})
	}
}

func insertLineBreaks(s string, width int) string {
	var builder strings.Builder
	for index := 0; index < len(s); index += width {
		end := index + width
		if end > len(s) {
			end = len(s)
		}
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(s[index:end])
	}
	return builder.String()
}

// TestReenrollPresentsClientCertificateDespiteCAHints pins the behaviour EST re-enrolment
// depends on. Go filters tls.Config.Certificates against the certificate_authorities hint
// a server sends, and silently sends nothing when no configured certificate matches. An
// EST server that asks for a client certificate but advertises a different CA list, which
// is common when the TLS chain and the issuing chain differ, would then see an
// unauthenticated request and reject the renewal.
func TestReenrollPresentsClientCertificateDespiteCAHints(t *testing.T) {
	// Given: a server that demands a client certificate while advertising a CA list that
	// does not include the issuer of the one the client holds.
	identity := newClientIdentity(t, "renewing.example.com")
	server := newClientAuthServer(t, newSelfSignedCertificate(t, "renewing.example.com"))

	client, err := New(Config{
		Server:            server.url,
		RootCAs:           server.trust,
		ClientCertificate: identity,
	})
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}

	// When: re-enrolling with no per-call identity, so the configured one is used.
	certificates, err := client.Reenroll(context.Background(), []byte{0x30, 0x00}, nil)

	// Then: the certificate was presented and the renewal succeeded.
	if err != nil {
		t.Fatalf("Reenroll returned error: %v", err)
	}
	if server.presented != "renewing.example.com" {
		t.Errorf("server saw client certificate %q, want renewing.example.com", server.presented)
	}
	if len(certificates) != 1 {
		t.Errorf("expected one certificate, got %d", len(certificates))
	}
}

// TestReenrollPrefersTheSuppliedIdentity covers the renewal path that matters in practice:
// the certificate being replaced is the one CertMagic holds, which is not known when the
// Client is built, so it has to be chosen per call.
func TestReenrollPrefersTheSuppliedIdentity(t *testing.T) {
	// Given: a client configured with one identity and handed another for this call.
	configured := newClientIdentity(t, "configured.example.com")
	current := newClientIdentity(t, "current.example.com")
	server := newClientAuthServer(t, newSelfSignedCertificate(t, "current.example.com"))

	client, err := New(Config{
		Server:            server.url,
		RootCAs:           server.trust,
		ClientCertificate: configured,
	})
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}

	// When
	if _, err := client.Reenroll(context.Background(), []byte{0x30, 0x00}, current); err != nil {
		t.Fatalf("Reenroll returned error: %v", err)
	}

	// Then
	if server.presented != "current.example.com" {
		t.Errorf("server saw client certificate %q, want current.example.com", server.presented)
	}
}

// TestReenrollDoesNotReuseAConnectionAcrossIdentities pins why each identity gets its own
// transport: a pooled connection carries the certificate it was handshaked with, so
// reusing one would authenticate a renewal as whoever went first.
func TestReenrollDoesNotReuseAConnectionAcrossIdentities(t *testing.T) {
	// Given
	first := newClientIdentity(t, "first.example.com")
	second := newClientIdentity(t, "second.example.com")
	server := newClientAuthServer(t, newSelfSignedCertificate(t, "renewed.example.com"))

	client, err := New(Config{Server: server.url, RootCAs: server.trust})
	if err != nil {
		t.Fatalf("constructing client: %v", err)
	}

	// When: two renewals in a row, with different identities.
	if _, err := client.Reenroll(context.Background(), []byte{0x30, 0x00}, first); err != nil {
		t.Fatalf("first Reenroll returned error: %v", err)
	}
	if server.presented != "first.example.com" {
		t.Fatalf("server saw client certificate %q on the first call", server.presented)
	}
	if _, err := client.Reenroll(context.Background(), []byte{0x30, 0x00}, second); err != nil {
		t.Fatalf("second Reenroll returned error: %v", err)
	}

	// Then
	if server.presented != "second.example.com" {
		t.Errorf("server saw client certificate %q on the second call, want second.example.com", server.presented)
	}
}

// clientAuthServer is an EST endpoint that records the client certificate it was shown. It
// advertises a CA list matching nothing the client holds, which is what makes Go's default
// certificate selection send nothing at all.
type clientAuthServer struct {
	url       string
	trust     *x509.CertPool
	presented string
}

func newClientAuthServer(t *testing.T, issued *x509.Certificate) *clientAuthServer {
	t.Helper()

	unrelatedCA := x509.NewCertPool()
	unrelatedCA.AddCert(newSelfSignedCertificate(t, "Some Other CA"))

	recorder := new(clientAuthServer)
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) == 0 {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("client certificate must be provided"))
				return
			}
			recorder.presented = r.TLS.PeerCertificates[0].Subject.CommonName
			w.Header().Set("Content-Type", mimeTypePKCS7)
			_, _ = w.Write(encodeCertsOnlyResponse(t, issued))
		}))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  unrelatedCA,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	recorder.url = server.URL
	recorder.trust = x509.NewCertPool()
	recorder.trust.AddCert(server.Certificate())
	return recorder
}
