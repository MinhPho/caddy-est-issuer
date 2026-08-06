// Package estlab reads the environment that aims the integration suites at an EST server.
//
// Both suites - the client's and the issuer's - take the same variables, and they live in
// different packages, so the contract is defined once here rather than written twice and
// left to drift.
package estlab

import (
	"os"
	"strings"
)

const (
	// DefaultServer is the lab started by "make lab", so a clean checkout runs the suites
	// with nothing set.
	DefaultServer = "https://127.0.0.1:8443"

	// DefaultDomain is reserved for documentation by RFC 2606, so a lab issuance can
	// never collide with a name someone owns.
	DefaultDomain = "example.com"
)

// Config aims a run at one EST server. The lab needs no label and no credentials and
// issues whatever name it is asked for; a real CA generally requires a label and HTTP
// Basic credentials, and issues only the names its profile permits.
type Config struct {
	Server   string
	Label    string
	Username string
	Password string

	// TrustedCAFile pins the anchor for the EST server's own TLS certificate. Empty
	// means the suite learns it over an unverified /cacerts, which is reasonable against
	// a lab on loopback and much less so across a network.
	TrustedCAFile string

	// Domain is the parent of the names the suite enrols, so a CA whose profile
	// constrains names can still be tested.
	Domain string
}

func ReadConfigFromEnv() Config {
	return Config{
		Server:        valueOr("EST_LAB_SERVER", DefaultServer),
		Label:         os.Getenv("EST_LAB_LABEL"),
		Username:      os.Getenv("EST_LAB_USERNAME"),
		Password:      os.Getenv("EST_LAB_PASSWORD"),
		TrustedCAFile: os.Getenv("EST_LAB_CA_FILE"),
		Domain:        valueOr("EST_LAB_DOMAIN", DefaultDomain),
	}
}

// NameFor builds a fully qualified name for a test to enrol, under the configured domain.
func (c Config) NameFor(label string) string {
	return label + "." + strings.TrimSuffix(c.Domain, ".")
}

func valueOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
