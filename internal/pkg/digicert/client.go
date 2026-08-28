// Package digicert is a thin client for DigiCert's CertCentral API — the
// Phase 6 renewal integration. This file is the ONE place in the app where
// DigiCert's actual wire format lives; DigiCertService and everything above
// it depends only on the Client interface below, never on HTTPClient or the
// request/response shapes directly, specifically so that if a payload shape
// here turns out wrong against a real account, only this file needs to
// change.
//
// IMPORTANT — UNVERIFIED WIRE FORMAT: there were no live DigiCert API
// credentials available while writing this, so the JSON request/response
// shapes and endpoint paths below are a best-effort reading of DigiCert's
// public CertCentral API v2 documentation, not something exercised against
// a real account. Confirmed independently of any live testing: DigiCert
// authenticates with a bare `X-DC-DEVKEY` header (no OAuth handshake), which
// this client relies on. Everything else — the exact product-type path
// segment, the request body's field names, how a custom (non-annual)
// validity period like a 47-day SC-081v3 renewal is actually expressed, the
// response envelope shape — needs confirming against a CertCentral sandbox
// account before pointing this at production. Until then, DigiCertService's
// unit tests exercise a fake Client, not this HTTPClient.
package digicert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OrderRequest is what's needed to place a new order or reissue an existing
// one — deliberately minimal, since everything product/organization-specific
// that a real CertCentral account requires is CertCentral account
// configuration, not something this app should need to know about per
// request.
type OrderRequest struct {
	// CSRPEM is the PEM-encoded signing request for a key pair this app
	// generated — see DigiCertService.Submit for why the key must already
	// exist and be stored before submission.
	CSRPEM       string
	CommonName   string
	DNSNames     []string
	ValidityDays int
}

// Order is a DigiCert order's identity and current state, as much as this
// client needs to track. Status is passed through verbatim in whatever
// vocabulary DigiCert's API actually uses ("pending", "issued", "denied",
// etc.) rather than mapped to a closed Go enum, so a status string this
// client doesn't yet have special handling for still displays to an admin
// instead of erroring.
type Order struct {
	OrderID string
	Status  string
}

// Client is the seam between DigiCertService and the network. A fake
// implementation backs every unit test in this codebase, since there is no
// live CertCentral account to test HTTPClient against yet — see the package
// doc comment above.
type Client interface {
	// SubmitOrder places a brand-new certificate order for a CSR this app
	// generated.
	SubmitOrder(ctx context.Context, req OrderRequest) (*Order, error)
	// SubmitReissue reissues an existing order — DigiCert's fast path for a
	// certificate that already has a DigiCert order on file, used instead of
	// SubmitOrder whenever the certificate being renewed carries a
	// DigiCertOrderID from an earlier order placed through this app.
	SubmitReissue(ctx context.Context, orderID string, req OrderRequest) (*Order, error)
	// OrderStatus polls an order's current state.
	OrderStatus(ctx context.Context, orderID string) (*Order, error)
	// DownloadCertificate fetches the issued certificate (PEM, leaf plus
	// chain) once OrderStatus reports it issued.
	DownloadCertificate(ctx context.Context, orderID string) ([]byte, error)
}

// HTTPClient is the real DigiCert CertCentral client. See the package doc
// comment: its exact request/response shapes are unverified.
type HTTPClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewHTTPClient builds a client against the given CertCentral base URL
// (e.g. "https://www.digicert.com/services/v2") and API dev key.
func NewHTTPClient(baseURL, apiKey string) *HTTPClient {
	return &HTTPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

var _ Client = (*HTTPClient)(nil)

// orderRequestBody is this client's best-effort reading of what CertCentral
// expects for a new-order/reissue body — UNVERIFIED, see package doc
// comment. In particular, how a short custom validity period (as opposed to
// DigiCert's traditional 1-2 year annual terms) is actually expressed is
// unconfirmed; validity_days is this client's own placeholder field name.
type orderRequestBody struct {
	Certificate struct {
		CommonName string   `json:"common_name"`
		CSR        string   `json:"csr"`
		DNSNames   []string `json:"dns_names,omitempty"`
	} `json:"certificate"`
	ValidityDays int `json:"validity_days,omitempty"`
}

// orderResponseBody is this client's best-effort reading of CertCentral's
// order response envelope — UNVERIFIED, see package doc comment.
type orderResponseBody struct {
	ID     json.Number `json:"id"`
	Status string      `json:"status"`
}

func (c *HTTPClient) SubmitOrder(ctx context.Context, req OrderRequest) (*Order, error) {
	body := orderRequestBody{ValidityDays: req.ValidityDays}
	body.Certificate.CommonName = req.CommonName
	body.Certificate.CSR = req.CSRPEM
	body.Certificate.DNSNames = req.DNSNames
	return c.doOrder(ctx, http.MethodPost, "/order/certificate/ssl_plus", body)
}

func (c *HTTPClient) SubmitReissue(ctx context.Context, orderID string, req OrderRequest) (*Order, error) {
	body := orderRequestBody{ValidityDays: req.ValidityDays}
	body.Certificate.CommonName = req.CommonName
	body.Certificate.CSR = req.CSRPEM
	body.Certificate.DNSNames = req.DNSNames
	return c.doOrder(ctx, http.MethodPost, fmt.Sprintf("/order/certificate/%s/reissue", orderID), body)
}

func (c *HTTPClient) OrderStatus(ctx context.Context, orderID string) (*Order, error) {
	return c.doOrder(ctx, http.MethodGet, fmt.Sprintf("/order/certificate/%s", orderID), nil)
}

func (c *HTTPClient) DownloadCertificate(ctx context.Context, orderID string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/certificate/%s/download/format/pem_all", orderID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("digicert: download certificate: unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("digicert: download certificate: reading response: %w", err)
	}
	return data, nil
}

func (c *HTTPClient) doOrder(ctx context.Context, method, path string, body any) (*Order, error) {
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("digicert: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out orderResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("digicert: decoding response: %w", err)
	}
	return &Order{OrderID: out.ID.String(), Status: out.Status}, nil
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("digicert: encoding request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("digicert: building request: %w", err)
	}
	req.Header.Set("X-DC-DEVKEY", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("digicert: request failed: %w", err)
	}
	return resp, nil
}

// StatusIsIssued reports whether a DigiCert order status string means the
// certificate is ready to download. Kept as a package-level function (not a
// method) since DigiCertService needs to interpret Order.Status regardless
// of which Client implementation produced it, including the fake used in
// tests.
func StatusIsIssued(status string) bool {
	return strings.EqualFold(status, "issued")
}
