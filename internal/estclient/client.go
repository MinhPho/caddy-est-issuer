// Package estclient implements the client half of the subset of RFC 7030 (Enrollment
// over Secure Transport) that a TLS server needs: discovering the CA chain, enrolling a
// new certificate, and re-enrolling an existing one.
//
// The package deliberately implements only the /cacerts, /simpleenroll and
// /simplereenroll operations. Server-side key generation (/serverkeygen) and CSR
// attribute discovery (/csrattrs) are out of scope: a TLS server must keep its own
// private key, and the attributes it needs are known from its own configuration.
package estclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/smallstep/pkcs7"
)

const (
	wellKnownPrefix = ".well-known/est"

	operationCACerts        = "cacerts"
	operationSimpleEnroll   = "simpleenroll"
	operationSimpleReenroll = "simplereenroll"

	mimeTypePKCS10 = "application/pkcs10"
	mimeTypePKCS7  = "application/pkcs7-mime"

	headerContentTransferEncoding = "Content-Transfer-Encoding"
	encodingBase64                = "base64"

	// EST payloads carry certificates, never bulk data. Capping the read keeps a
	// misbehaving or hostile server from exhausting memory.
	maxResponseBytes = 1 << 20
)

// ProtocolError reports an EST response that was reached but not understood, so callers
// can distinguish a server that refused enrolment from a network or TLS failure.
type ProtocolError struct {
	Operation  string
	StatusCode int
	Detail     string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("est: %s failed with status %d: %s", e.Operation, e.StatusCode, e.Detail)
}

// Config describes how to reach one EST server. The zero value is not usable; build a
// Client with New, which validates it.
type Config struct {
	// Server is the base URL of the EST server, e.g. https://pki.example.com:8443.
	// The /.well-known/est path is appended by this package.
	Server string

	// Label is the optional EST label (RFC 7030 section 3.2.2), which some CAs use to
	// select an enrolment profile. Empty means no label segment.
	Label string

	// Username and Password enable HTTP Basic authentication. EST calls this the
	// "certificate-less" client authentication mode and requires it over TLS only.
	Username string
	Password string

	// ClientCertificate authenticates the client with TLS, which is what
	// /simplereenroll expects: the client proves possession of the certificate it is
	// asking to replace.
	ClientCertificate *tls.Certificate

	// RootCAs verifies the EST server's own TLS certificate. Nil uses the host trust
	// store, which is the right default for a publicly issued server certificate.
	RootCAs *x509.CertPool

	// InsecureSkipVerify disables verification of the EST server's TLS certificate.
	// It exists for bootstrapping against a lab CA whose root is not yet trusted and
	// must not be used in production.
	InsecureSkipVerify bool
}

// Client talks to a single EST server.
type Client struct {
	baseURL    *url.URL
	label      string
	username   string
	password   string
	tlsConfig  *tls.Config
	httpClient *http.Client
}

// New validates cfg and constructs a Client with an HTTP client wired for the configured
// authentication and trust settings.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Server) == "" {
		return nil, errors.New("est: server URL is required")
	}
	parsed, err := url.Parse(cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("est: server URL %q is not a valid URL: %w", cfg.Server, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("est: server URL must use https, got %q", parsed.Scheme)
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.ClientCertificate != nil {
		presentAlways(tlsConfig, cfg.ClientCertificate)
	}

	return &Client{
		baseURL:   parsed,
		label:     strings.Trim(cfg.Label, "/"),
		username:  cfg.Username,
		password:  cfg.Password,
		tlsConfig: tlsConfig,
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// presentAlways makes the handshake offer certificate unconditionally.
//
// GetClientCertificate rather than Certificates: Go filters Certificates against the
// certificate_authorities hint the server sends and silently presents nothing when nothing
// matches. An EST server's TLS chain need not share an issuer with the certificate being
// renewed, so that filter turns a valid re-enrolment into an unauthenticated request.
// There is only ever one candidate here, so there is nothing to select between.
func presentAlways(tlsConfig *tls.Config, certificate *tls.Certificate) {
	offered := *certificate
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &offered, nil
	}
}

// CACerts retrieves the CA certificate chain the server issues from. RFC 7030 requires a
// client to fetch and trust this before relying on an enrolled certificate.
func (c *Client) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	return c.roundTrip(ctx, c.httpClient, http.MethodGet, operationCACerts, nil)
}

// Enroll requests a new certificate for the given DER-encoded PKCS#10 request.
func (c *Client) Enroll(ctx context.Context, csrDER []byte) ([]*x509.Certificate, error) {
	return c.roundTrip(ctx, c.httpClient, http.MethodPost, operationSimpleEnroll, csrDER)
}

// Reenroll renews an existing certificate, authenticated by identity: the certificate being
// replaced, which RFC 7030 section 4.2.2 expects the client to present. A nil identity
// falls back to Config.ClientCertificate, and re-enrolling with neither will be refused by
// any server that follows the specification.
func (c *Client) Reenroll(ctx context.Context, csrDER []byte, identity *tls.Certificate) ([]*x509.Certificate, error) {
	if identity == nil {
		return c.roundTrip(ctx, c.httpClient, http.MethodPost, operationSimpleReenroll, csrDER)
	}

	// A connection in the shared pool carries the certificate it was handshaked with, so
	// borrowing one would authenticate this renewal as whoever opened it. Renewals happen
	// once per certificate lifetime, which makes a dedicated connection cheap.
	transport := &http.Transport{TLSClientConfig: c.tlsConfig.Clone()}
	presentAlways(transport.TLSClientConfig, identity)
	defer transport.CloseIdleConnections()

	return c.roundTrip(ctx, &http.Client{Transport: transport}, http.MethodPost, operationSimpleReenroll, csrDER)
}

func (c *Client) endpoint(operation string) string {
	segments := []string{strings.TrimSuffix(c.baseURL.Path, "/"), wellKnownPrefix}
	if c.label != "" {
		segments = append(segments, c.label)
	}
	segments = append(segments, operation)

	resolved := *c.baseURL
	resolved.Path = strings.Join(segments, "/")
	return resolved.String()
}

func (c *Client) roundTrip(ctx context.Context, httpClient *http.Client, method, operation string, csrDER []byte) ([]*x509.Certificate, error) {
	request, err := c.buildRequest(ctx, method, operation, csrDER)
	if err != nil {
		return nil, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("est: %s request failed: %w", operation, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("est: reading %s response failed: %w", operation, err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, &ProtocolError{
			Operation:  operation,
			StatusCode: response.StatusCode,
			Detail:     summarize(body),
		}
	}

	certificates, err := ParseCertsOnlyPKCS7(body)
	if err != nil {
		return nil, fmt.Errorf("est: %s returned an unusable body: %w", operation, err)
	}
	return certificates, nil
}

func (c *Client) buildRequest(ctx context.Context, method, operation string, csrDER []byte) (*http.Request, error) {
	var body io.Reader
	if csrDER != nil {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(csrDER)))
		base64.StdEncoding.Encode(encoded, csrDER)
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.endpoint(operation), body)
	if err != nil {
		return nil, fmt.Errorf("est: building %s request failed: %w", operation, err)
	}

	request.Header.Set("Accept", mimeTypePKCS7)
	if csrDER != nil {
		request.Header.Set("Content-Type", mimeTypePKCS10)
		request.Header.Set(headerContentTransferEncoding, encodingBase64)
	}
	if c.username != "" {
		request.SetBasicAuth(c.username, c.password)
	}
	return request, nil
}

// ParseCertsOnlyPKCS7 decodes an EST response body into certificates. The body is a
// base64-encoded degenerate PKCS#7 "certs-only" structure; servers vary in whether they
// wrap the base64 in PEM armour or split it across lines, so both are tolerated.
func ParseCertsOnlyPKCS7(body []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty response body")
	}

	der, err := decodeBase64Tolerant(trimmed)
	if err != nil {
		return nil, err
	}

	parsed, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7 structure: %w", err)
	}
	if len(parsed.Certificates) == 0 {
		return nil, errors.New("PKCS#7 structure carried no certificates")
	}
	return parsed.Certificates, nil
}

func decodeBase64Tolerant(body []byte) ([]byte, error) {
	// Strip PEM armour and any line breaks the server inserted; base64 decoders reject
	// embedded newlines, and RFC 7030 does not forbid them.
	var builder strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		builder.WriteString(line)
	}

	der, err := base64.StdEncoding.DecodeString(builder.String())
	if err != nil {
		return nil, fmt.Errorf("decoding base64 payload: %w", err)
	}
	return der, nil
}

func summarize(body []byte) string {
	const limit = 200
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "(empty body)"
	}
	if len(text) > limit {
		return text[:limit] + "..."
	}
	return text
}
