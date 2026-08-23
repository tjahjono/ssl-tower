package certutil

import (
	"crypto/x509"
	"fmt"
	"time"
)

// ChainValidation is the result of checking a certificate chain's internal
// consistency: does each certificate actually sign the one before it, is
// every intermediate marked as a CA, and is nothing expired or not yet
// valid. It deliberately does not check trust against any root store — an
// internal PKI's root is commonly self-signed and never meant to be in a
// public trust store, so "does this chain of custody hold together" is the
// useful question here, not "would a browser trust it".
type ChainValidation struct {
	Valid  bool
	Issues []string
}

// ValidateChain checks chain against leaf: chain[0] must have signed leaf,
// chain[1] must have signed chain[0], and so on. An empty chain is
// trivially valid — there's nothing to check, and a missing chain is a
// separate, already-surfaced concern (see domain.Certificate.HealthFindings's
// "no intermediates supplied" finding).
func ValidateChain(leaf *x509.Certificate, chain []*x509.Certificate) ChainValidation {
	var issues []string
	now := time.Now()

	seq := make([]*x509.Certificate, 0, len(chain)+1)
	seq = append(seq, leaf)
	seq = append(seq, chain...)

	for i, c := range seq {
		label := "the certificate"
		if i > 0 {
			label = fmt.Sprintf("intermediate #%d (%s)", i, labelFor(c))
		}
		if now.Before(c.NotBefore) {
			issues = append(issues, label+" is not valid yet — starts "+c.NotBefore.Format("2 Jan 2006"))
		}
		if now.After(c.NotAfter) {
			issues = append(issues, label+" has expired — was valid until "+c.NotAfter.Format("2 Jan 2006"))
		}
	}

	for i, signer := range chain {
		signed := seq[i] // leaf when i == 0, otherwise chain[i-1]
		signedLabel := "the certificate"
		if i > 0 {
			signedLabel = fmt.Sprintf("intermediate #%d (%s)", i, labelFor(signed))
		}
		if !signer.BasicConstraintsValid || !signer.IsCA {
			issues = append(issues, fmt.Sprintf("intermediate #%d (%s) is not marked as a CA", i+1, labelFor(signer)))
		}
		if err := signed.CheckSignatureFrom(signer); err != nil {
			issues = append(issues, fmt.Sprintf("intermediate #%d (%s) does not appear to have signed %s: %s", i+1, labelFor(signer), signedLabel, err))
		}
	}

	return ChainValidation{Valid: len(issues) == 0, Issues: issues}
}

// labelFor renders a short, human-readable name for a certificate in a
// validation message — its subject common name, falling back to the full
// subject string when there isn't one.
func labelFor(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
