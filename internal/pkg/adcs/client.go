// Package adcs implements a client for ADCS (Active Directory Certificate
// Services), Microsoft's PKI server role for Windows Server — specifically
// its Certificate Enrollment Web Service (CES), speaking the MS-WSTEP wire
// protocol over HTTPS with a WS-Security UsernameToken. This targets CES's
// username/password authentication profile deliberately, not Windows
// Integrated (Kerberos) or client-certificate auth — the only one of the
// three that works from a non-domain-joined, cross-platform Go process with
// no extra OS-specific dependency.
//
// There is no CEP (Certificate Enrollment Policy, MS-XCEP) support here —
// policy discovery is skipped entirely in favor of a fixed, admin-configured
// CES endpoint and certificate template name (Config.Endpoint/Template),
// mirroring how internal/pkg/digicert takes a fixed base URL rather than
// discovering one. A from-scratch PKCS#10 request this package builds
// carries no Microsoft template extension of its own, so Template is sent
// as a WS-Trust AdditionalContext item instead — ADCS honours that for a
// CES endpoint that isn't itself scoped to a single template.
//
// Unverified against a real ADCS server, same caveat internal/pkg/digicert
// already carries: every wire-format detail here is a careful reading of
// Microsoft's published MS-WSTEP specification and documented examples, not
// something exercised against a live CES endpoint. See CLAUDE.md's ADCS
// section for the live-verification checklist to run through once a real
// server is available.
package adcs

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

// Config configures a Client's connection to one ADCS CES endpoint.
type Config struct {
	// Endpoint is the full CES URL configured for username/password
	// authentication — e.g.
	// "https://adcs.example.com/ADPolicyProvider_CEP_UsernamePassword/service.svc/CES".
	// Not a bare hostname; this comes from ADCS's own admin console.
	Endpoint string
	// Username/Password authenticate via a WS-Security UsernameToken
	// (PasswordText, relying on the endpoint being HTTPS for
	// confidentiality — the same assumption ADCS's own username/password
	// CES profile makes).
	Username string
	Password string
	// Template is the certificate template's short ("common") name ADCS
	// should issue against, sent as a WS-Trust AdditionalContext item.
	Template string
	// HTTPClient overrides the default *http.Client — tests point this at
	// an httptest.Server; production leaves it nil.
	HTTPClient *http.Client
}

// EnrollResult is what a successful Enroll call returns.
type EnrollResult struct {
	// Certificates is the issued certificate chain, leaf first, decoded
	// from the response's degenerate PKCS#7 BinarySecurityToken. Ordered by
	// matching each certificate's public key against the original CSR's —
	// unlike a signed PKCS#7, a certs-only "degenerate" one has no
	// guaranteed ordering, so this isn't simply "whatever came back first."
	Certificates []*x509.Certificate
	// RequestID is the CA's own request/serial ID for this issuance, if the
	// response carried one — purely informational, never required.
	RequestID string
	// Disposition is the raw disposition message ADCS returned (e.g.
	// "Issued"). A template requiring manual approval returns a *pending*
	// disposition and no certificate at all — Enroll treats that as an
	// error, since this app has no concept of an asynchronous wait on an
	// internal signing path (contrast with the DigiCert integration, which
	// is built around exactly that kind of async order+poll).
	Disposition string
}

// Client enrolls a PKCS#10 request against ADCS and returns the issued
// certificate. HTTPClient is the one production implementation; tests use a
// fake, the same shape internal/pkg/digicert's Client interface already
// established.
type Client interface {
	Enroll(ctx context.Context, csrDER []byte) (*EnrollResult, error)
}

// HTTPClient is the real ADCS CES client.
type HTTPClient struct {
	cfg Config
}

// NewHTTPClient builds a Client from cfg.
func NewHTTPClient(cfg Config) *HTTPClient {
	return &HTTPClient{cfg: cfg}
}

var _ Client = (*HTTPClient)(nil)

func (c *HTTPClient) httpClient() *http.Client {
	if c.cfg.HTTPClient != nil {
		return c.cfg.HTTPClient
	}
	return http.DefaultClient
}

// Enroll submits csrDER (a DER-encoded PKCS#10 request) to ADCS's CES
// endpoint and returns the issued certificate chain.
func (c *HTTPClient) Enroll(ctx context.Context, csrDER []byte) (*EnrollResult, error) {
	reqBody, err := buildRequestEnvelope(c.cfg, csrDER)
	if err != nil {
		return nil, fmt.Errorf("adcs: build request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("adcs: build http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("adcs: request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("adcs: read response: %w", err)
	}

	// A SOAP fault can arrive with any HTTP status (ADCS commonly answers
	// an auth failure or a rejected request with 500 and a SOAP Fault body,
	// but checking for a fault regardless of status code is more robust
	// than trusting the HTTP layer alone to signal failure).
	if fault := parseSOAPFault(respBody); fault != "" {
		return nil, fmt.Errorf("adcs: %s", fault)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("adcs: unexpected HTTP status %d", resp.StatusCode)
	}

	result, err := parseResponseEnvelope(respBody)
	if err != nil {
		return nil, fmt.Errorf("adcs: parse response: %w", err)
	}
	if err := orderCertificatesFromCSR(result, csrDER); err != nil {
		return nil, fmt.Errorf("adcs: %w", err)
	}
	return result, nil
}
