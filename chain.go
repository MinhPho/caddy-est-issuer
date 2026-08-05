package caddyest

import (
	"bytes"
	"crypto/x509"
)

// buildPresentedChain assembles the certificates a TLS server sends during a handshake:
// the leaf first, then each intermediate up to but excluding the root. EST allows a server
// to answer /simpleenroll with the leaf alone, which no client can build a path from, so
// the missing links are taken from whatever the caller has - the rest of the enrolment
// response, then /cacerts.
//
// The second return value reports whether the path terminates at a self-signed root. When
// it is false the chain is still usable by clients that already hold the issuing CA, but
// the caller has no proof the chain is complete and should say so.
func buildPresentedChain(issued, caCerts []*x509.Certificate) ([]*x509.Certificate, bool) {
	if len(issued) == 0 {
		return nil, false
	}

	pool := make([]*x509.Certificate, 0, len(issued)-1+len(caCerts))
	pool = append(pool, issued[1:]...)
	pool = append(pool, caCerts...)

	path, isRooted := orderCertificateChain(issued[0], pool)
	if isRooted && len(path) > 1 {
		// The root is dropped: a client that does not already trust it gains nothing from
		// receiving it, and it costs bytes on every handshake.
		path = path[:len(path)-1]
	}
	return path, isRooted
}

// orderCertificateChain walks from leaf to issuer through pool, consuming each certificate
// it uses so a cross-signed pair cannot send it round in circles.
func orderCertificateChain(leaf *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, bool) {
	path := []*x509.Certificate{leaf}
	if isSelfSigned(leaf) {
		return path, true
	}

	remaining := append([]*x509.Certificate(nil), pool...)
	current := leaf
	for {
		index := indexOfIssuer(current, remaining)
		if index < 0 {
			return path, false
		}

		parent := remaining[index]
		remaining = append(remaining[:index], remaining[index+1:]...)
		path = append(path, parent)
		if isSelfSigned(parent) {
			return path, true
		}
		current = parent
	}
}

// indexOfIssuer verifies the signature rather than trusting the subject match alone, so a
// name collision between two CAs cannot produce a chain that fails at the client.
func indexOfIssuer(certificate *x509.Certificate, candidates []*x509.Certificate) int {
	for index, candidate := range candidates {
		if !bytes.Equal(candidate.RawSubject, certificate.RawIssuer) {
			continue
		}
		if certificate.CheckSignatureFrom(candidate) == nil {
			return index
		}
	}
	return -1
}

func isSelfSigned(certificate *x509.Certificate) bool {
	return bytes.Equal(certificate.RawSubject, certificate.RawIssuer) &&
		certificate.CheckSignatureFrom(certificate) == nil
}
