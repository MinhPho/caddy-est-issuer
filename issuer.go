// Package caddyest lets Caddy obtain and renew its own TLS certificates over EST
// (RFC 7030) instead of ACME, by registering a CertMagic issuer under the Caddy module
// ID tls.issuance.est.
//
// This is the opposite direction from an EST server module: here Caddy is the EST
// client, and the certificate authority is an external EST-speaking CA.
package caddyest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/MinhPho/caddy-est-issuer/internal/estclient"
)

func init() {
	caddy.RegisterModule(Issuer{})
}

// Issuer obtains certificates from an EST server. It implements certmagic.Issuer, so
// Caddy drives it through the same lifecycle as its ACME issuer.
type Issuer struct {
	// Server is the base URL of the EST server, e.g. https://pki.example.com:8443.
	Server string `json:"server,omitempty"`

	// Label selects an enrolment profile on servers that use EST labels. Some CAs call
	// this the EST alias.
	Label string `json:"label,omitempty"`

	// Username and Password enable HTTP Basic authentication. Prefer a Caddy
	// placeholder such as {env.EST_PASSWORD} over a literal in the config file.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// TrustedCAFile is a PEM bundle used to verify the EST server's own TLS
	// certificate. Empty uses the system trust store.
	TrustedCAFile string `json:"trusted_ca_file,omitempty"`

	// ClientCertificateFile and ClientKeyFile authenticate this client with TLS on
	// requests that have no certificate of their own to present, which is every request
	// but a renewal. A renewal presents the certificate it is replacing, taken from
	// CertMagic's store.
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	ClientKeyFile         string `json:"client_key_file,omitempty"`

	// InsecureSkipVerify disables verification of the EST server's TLS certificate.
	// Intended for bootstrapping against a lab CA; never enable it in production.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	logger  *zap.Logger
	client  *estclient.Client
	storage certmagic.Storage
	caChain *caChainCache

	// fetchCACerts is the seam tests substitute for a live /cacerts call.
	fetchCACerts func(context.Context) ([]*x509.Certificate, error)
}

// caChainCache holds the /cacerts response for the lifetime of the process. It is filled
// lazily rather than in Provision so that an EST server which is briefly unreachable
// delays a certificate instead of preventing Caddy from starting. Held by pointer because
// Caddy calls CaddyModule on a zero value of Issuer, which must stay copyable.
type caChainCache struct {
	mu           sync.Mutex
	certificates []*x509.Certificate
}

func (c *caChainCache) get(ctx context.Context, fetch func(context.Context) ([]*x509.Certificate, error)) ([]*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.certificates != nil {
		return c.certificates, nil
	}
	certificates, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.certificates = certificates
	return certificates, nil
}

// CaddyModule returns the Caddy module information.
func (Issuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.est",
		New: func() caddy.Module { return new(Issuer) },
	}
}

// Provision resolves configuration placeholders and builds the EST client.
func (iss *Issuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger(iss)
	iss.caChain = new(caChainCache)

	replacer := caddy.NewReplacer()
	iss.Server = replacer.ReplaceAll(iss.Server, "")
	iss.Label = replacer.ReplaceAll(iss.Label, "")
	iss.Username = replacer.ReplaceAll(iss.Username, "")
	iss.Password = replacer.ReplaceAll(iss.Password, "")

	config, err := iss.buildClientConfig()
	if err != nil {
		return err
	}

	client, err := estclient.New(config)
	if err != nil {
		return err
	}
	iss.client = client
	iss.fetchCACerts = client.CACerts

	if iss.InsecureSkipVerify {
		iss.logger.Warn("EST server certificate verification is disabled; do not use this outside a lab")
	}
	return nil
}

func (iss *Issuer) buildClientConfig() (estclient.Config, error) {
	config := estclient.Config{
		Server:             iss.Server,
		Label:              iss.Label,
		Username:           iss.Username,
		Password:           iss.Password,
		InsecureSkipVerify: iss.InsecureSkipVerify,
	}

	if iss.TrustedCAFile != "" {
		pool, err := loadCertPool(iss.TrustedCAFile)
		if err != nil {
			return estclient.Config{}, err
		}
		config.RootCAs = pool
	}

	hasCert, hasKey := iss.ClientCertificateFile != "", iss.ClientKeyFile != ""
	if hasCert != hasKey {
		return estclient.Config{}, fmt.Errorf(
			"client_certificate_file and client_key_file must be set together")
	}
	if hasCert {
		keyPair, err := tls.LoadX509KeyPair(iss.ClientCertificateFile, iss.ClientKeyFile)
		if err != nil {
			return estclient.Config{}, fmt.Errorf("loading EST client key pair: %w", err)
		}
		config.ClientCertificate = &keyPair
	}
	return config, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	bundle, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trusted CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("trusted CA file %q contained no PEM certificates", path)
	}
	return pool, nil
}

// Validate rejects a configuration that Provision would only fail on at first issuance.
func (iss *Issuer) Validate() error {
	if strings.TrimSpace(iss.Server) == "" {
		return fmt.Errorf("an EST server URL is required")
	}
	return nil
}

// IssuerKey identifies this issuer in CertMagic's storage layout. Including the label
// keeps certificates from two aliases on the same server in separate buckets.
func (iss *Issuer) IssuerKey() string {
	key := iss.Server
	if iss.Label != "" {
		key += "/" + iss.Label
	}
	return key
}

// Issue obtains a certificate for the request, choosing between EST enrolment and
// re-enrolment.
//
// CertMagic has no separate renewal entry point: it calls Issue for both the first
// issuance and every renewal. EST does distinguish /simpleenroll from /simplereenroll,
// and a CA may apply different authorisation rules to each, so the certificate CertMagic
// currently holds decides which one this is.
func (iss *Issuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("est: issuing requires a certificate request")
	}

	operation, identity := iss.chooseOperation(ctx, csr)
	call := iss.client.Enroll
	if operation == operationReenroll {
		call = func(ctx context.Context, csrDER []byte) ([]*x509.Certificate, error) {
			return iss.client.Reenroll(ctx, csrDER, identity)
		}
	}
	return iss.enroll(ctx, csr, call, operation)
}

const (
	operationEnroll   = "enroll"
	operationReenroll = "reenroll"
)

// chooseOperation reports which EST operation the request needs and, for a renewal, the
// certificate that authenticates it: the one being replaced, which is what RFC 7030
// section 4.2.2 expects a client to present.
//
// A storage failure enrols instead of failing. Enrolling a name the CA considers already
// issued may be refused, but leaving Caddy with no certificate at all is the worse of the
// two outcomes.
func (iss *Issuer) chooseOperation(ctx context.Context, csr *x509.CertificateRequest) (string, *tls.Certificate) {
	current, err := iss.findCurrentCertificate(ctx, csr)
	if err != nil {
		iss.logger.Warn("could not read the current certificate, so enrolling as if the name were new",
			zap.String("server", iss.Server),
			zap.Error(err))
		return operationEnroll, nil
	}
	if current == nil {
		return operationEnroll, nil
	}
	return operationReenroll, current
}

type enrollFunc func(context.Context, []byte) ([]*x509.Certificate, error)

func (iss *Issuer) enroll(ctx context.Context, csr *x509.CertificateRequest, call enrollFunc, operation string) (*certmagic.IssuedCertificate, error) {
	certificates, err := call(ctx, csr.Raw)
	if err != nil {
		return nil, err
	}

	chain, isRooted := buildPresentedChain(certificates, nil)
	if !isRooted {
		chain, isRooted = iss.completeChain(ctx, certificates)
	}
	if !isRooted {
		iss.logger.Warn("serving an incomplete certificate chain; clients that do not already trust the issuing CA will reject it",
			zap.String("server", iss.Server),
			zap.String("label", iss.Label),
			zap.Int("chain_length", len(chain)))
	}

	iss.logger.Info("obtained certificate over EST",
		zap.String("operation", operation),
		zap.String("server", iss.Server),
		zap.String("label", iss.Label),
		zap.Int("chain_length", len(chain)))

	return &certmagic.IssuedCertificate{Certificate: encodeChainPEM(chain)}, nil
}

// completeChain fills in the issuers an EST server left out of the enrolment response.
// A failure here is not fatal: the leaf alone still works for clients that hold the
// issuing CA already, and refusing the certificate would be the worse outcome.
func (iss *Issuer) completeChain(ctx context.Context, issued []*x509.Certificate) ([]*x509.Certificate, bool) {
	if iss.fetchCACerts == nil || iss.caChain == nil {
		return buildPresentedChain(issued, nil)
	}

	caCerts, err := iss.caChain.get(ctx, iss.fetchCACerts)
	if err != nil {
		iss.logger.Warn("could not retrieve the CA chain over EST",
			zap.String("server", iss.Server),
			zap.Error(err))
		return buildPresentedChain(issued, nil)
	}
	return buildPresentedChain(issued, caCerts)
}

// encodeChainPEM renders the leaf first, matching what a TLS server expects to present.
func encodeChainPEM(certificates []*x509.Certificate) []byte {
	var chain []byte
	for _, certificate := range certificates {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})...)
	}
	return chain
}

// UnmarshalCaddyfile parses the est issuer block:
//
//	issuer est {
//	    server https://pki.example.com:8443
//	    label caddyest
//	    username robot
//	    password {env.EST_PASSWORD}
//	    trusted_ca_file /etc/caddy/est-ca.pem
//	    client_certificate_file /etc/caddy/est-client.pem
//	    client_key_file /etc/caddy/est-client-key.pem
//	    insecure_skip_verify
//	}
func (iss *Issuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			directive := d.Val()

			target, expectsValue := iss.stringTarget(directive)
			if expectsValue {
				if !d.NextArg() {
					return d.ArgErr()
				}
				*target = d.Val()
				continue
			}

			if directive == "insecure_skip_verify" {
				if d.NextArg() {
					return d.ArgErr()
				}
				iss.InsecureSkipVerify = true
				continue
			}
			return d.Errf("unrecognized est option '%s'", directive)
		}
	}
	return nil
}

func (iss *Issuer) stringTarget(directive string) (*string, bool) {
	switch directive {
	case "server":
		return &iss.Server, true
	case "label":
		return &iss.Label, true
	case "username":
		return &iss.Username, true
	case "password":
		return &iss.Password, true
	case "trusted_ca_file":
		return &iss.TrustedCAFile, true
	case "client_certificate_file":
		return &iss.ClientCertificateFile, true
	case "client_key_file":
		return &iss.ClientKeyFile, true
	default:
		return nil, false
	}
}

// configSetter restates caddytls.ConfigSetter, which Caddy calls to hand an issuer the
// CertMagic configuration it is driven with.
//
// Declared here rather than imported: importing caddytls for one interface would pull
// Caddy's whole TLS dependency graph into this module's go.mod, and Go satisfies
// interfaces structurally, so the import buys nothing but weight. If Caddy ever changes
// the signature, this guard keeps compiling and SetConfig silently stops being called -
// which the integration tests catch, since a renewal then finds no storage.
type configSetter interface {
	SetConfig(cfg *certmagic.Config)
}

// Interface guards.
var (
	_ caddy.Module          = (*Issuer)(nil)
	_ caddy.Provisioner     = (*Issuer)(nil)
	_ caddy.Validator       = (*Issuer)(nil)
	_ certmagic.Issuer      = (*Issuer)(nil)
	_ caddyfile.Unmarshaler = (*Issuer)(nil)
	_ configSetter          = (*Issuer)(nil)
)
