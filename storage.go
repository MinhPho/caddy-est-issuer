package caddyest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

// SetConfig receives the CertMagic configuration Caddy drives this issuer with, which is
// how the issuer reaches the certificate store. Caddy calls it on every issuer in an
// automation policy at provision time and again on reload.
func (iss *Issuer) SetConfig(cfg *certmagic.Config) {
	iss.storage = cfg.Storage
}

// findCurrentCertificate returns the certificate CertMagic holds for the CSR's names under
// this issuer, or nil when there is none, which is what distinguishes a renewal from a
// first enrolment.
func (iss *Issuer) findCurrentCertificate(ctx context.Context, csr *x509.CertificateRequest) (*tls.Certificate, error) {
	if iss.storage == nil {
		iss.logger.Warn("no certificate storage is available, so every issuance enrols as new",
			zap.String("server", iss.Server))
		return nil, nil
	}

	namesKey := storageNamesKey(csr)
	certificatePEM, err := iss.storage.Load(ctx, certmagic.StorageKeys.SiteCert(iss.IssuerKey(), namesKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("est: reading the stored certificate for %q: %w", namesKey, err)
	}

	keyPEM, err := iss.storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(iss.IssuerKey(), namesKey))
	if err != nil {
		return nil, fmt.Errorf("est: reading the private key stored with the certificate for %q: %w", namesKey, err)
	}

	current, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("est: the stored certificate for %q is unusable: %w", namesKey, err)
	}
	return &current, nil
}

// storageNamesKey derives the storage key CertMagic files a certificate under.
//
// CertMagic builds it from an unexported helper, so the derivation is replicated here and
// pinned by a test against CertificateResource.NamesKey. If the two ever diverge, a
// renewal stops finding its certificate and enrols instead, which a server may refuse but
// which cannot serve the wrong certificate.
func storageNamesKey(csr *x509.CertificateRequest) string {
	var names []string
	if csr.Subject.CommonName != "" {
		names = append(names, csr.Subject.CommonName)
	}
	names = append(names, csr.DNSNames...)
	names = append(names, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		names = append(names, ip.String())
	}
	for _, uri := range csr.URIs {
		names = append(names, uri.String())
	}

	resource := certmagic.CertificateResource{SANs: names}
	// CertMagic normalises the key the same way. A name it rejects is one it could not have
	// stored either, so the best-effort result simply finds nothing and the issuance enrols.
	normalized, _ := idna.ToASCII(resource.NamesKey())
	return normalized
}
