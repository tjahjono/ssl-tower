package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mozilla.org/pkcs7"
)

func mustGenerateCSR(t *testing.T, commonName string) (der []byte, pub any) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return der, key.Public()
}

// mustSelfSignedCert builds a throwaway self-signed certificate — used as a
// realistic "issued leaf" fixture. If pub is non-nil, the certificate is
// issued for that exact public key (so it matches a given CSR); otherwise
// it mints its own, unrelated key pair (a decoy/intermediate fixture).
func mustSelfSignedCert(t *testing.T, commonName string, pub any) []byte {
	t.Helper()
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	subjectPub := pub
	if subjectPub == nil {
		subjectPub = &signerKey.PublicKey
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, subjectPub, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestBuildRequestEnvelopeCarriesEveryField(t *testing.T) {
	csrDER, _ := mustGenerateCSR(t, "app.example.com")
	body, err := buildRequestEnvelope(Config{
		Endpoint: "https://adcs.example.com/CES",
		Username: `CORP\svc-adcs`,
		Password: `p@ss<word>&"'`,
		Template: "WebServer",
	}, csrDER)
	if err != nil {
		t.Fatalf("buildRequestEnvelope: %v", err)
	}

	var decoded struct {
		Header struct {
			To       string `xml:"To"`
			Security struct {
				UsernameToken struct {
					Username string `xml:"Username"`
					Password string `xml:"Password"`
				} `xml:"UsernameToken"`
			} `xml:"Security"`
		} `xml:"Header"`
		Body struct {
			RST struct {
				BinarySecurityToken string `xml:"BinarySecurityToken"`
				AdditionalContext   struct {
					ContextItem struct {
						Name  string `xml:"Name,attr"`
						Value string `xml:"Value"`
					} `xml:"ContextItem"`
				} `xml:"AdditionalContext"`
			} `xml:"RequestSecurityToken"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the built envelope is not valid XML: %v\n%s", err, body)
	}

	if decoded.Header.To != "https://adcs.example.com/CES" {
		t.Errorf("To = %q, want the configured endpoint", decoded.Header.To)
	}
	if decoded.Header.Security.UsernameToken.Username != `CORP\svc-adcs` {
		t.Errorf("Username = %q, want %q", decoded.Header.Security.UsernameToken.Username, `CORP\svc-adcs`)
	}
	if decoded.Header.Security.UsernameToken.Password != `p@ss<word>&"'` {
		t.Errorf("Password = %q, want it round-tripped exactly despite special characters", decoded.Header.Security.UsernameToken.Password)
	}
	if decoded.Body.RST.AdditionalContext.ContextItem.Name != "CertificateTemplate" {
		t.Errorf("AdditionalContext ContextItem Name = %q, want CertificateTemplate", decoded.Body.RST.AdditionalContext.ContextItem.Name)
	}
	if decoded.Body.RST.AdditionalContext.ContextItem.Value != "WebServer" {
		t.Errorf("requested template = %q, want %q", decoded.Body.RST.AdditionalContext.ContextItem.Value, "WebServer")
	}
	gotCSR, err := base64.StdEncoding.DecodeString(decoded.Body.RST.BinarySecurityToken)
	if err != nil {
		t.Fatalf("BinarySecurityToken is not valid base64: %v", err)
	}
	if string(gotCSR) != string(csrDER) {
		t.Error("the embedded BinarySecurityToken does not round-trip the original CSR DER")
	}
}

func TestParseResponseEnvelopeExtractsIssuedCertificate(t *testing.T) {
	certDER := mustSelfSignedCert(t, "issued.example.com", nil)
	degenerate, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		t.Fatalf("DegenerateCertificate: %v", err)
	}
	respXML := fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <RequestSecurityTokenResponse>
        <TokenType>http://schemas.microsoft.com/windows/pki/2009/01/enrollment</TokenType>
        <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">Issued</DispositionMessage>
        <BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS7" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#base64binary">%s</BinarySecurityToken>
        <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">1234</RequestID>
      </RequestSecurityTokenResponse>
    </RequestSecurityTokenResponseCollection>
  </s:Body>
</s:Envelope>`, base64.StdEncoding.EncodeToString(degenerate))

	result, err := parseResponseEnvelope([]byte(respXML))
	if err != nil {
		t.Fatalf("parseResponseEnvelope: %v", err)
	}
	if result.RequestID != "1234" {
		t.Errorf("RequestID = %q, want %q", result.RequestID, "1234")
	}
	if result.Disposition != "Issued" {
		t.Errorf("Disposition = %q, want %q", result.Disposition, "Issued")
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("Certificates = %d entries, want 1", len(result.Certificates))
	}
	if result.Certificates[0].Subject.CommonName != "issued.example.com" {
		t.Errorf("issued certificate CN = %q, want %q", result.Certificates[0].Subject.CommonName, "issued.example.com")
	}
}

func TestParseResponseEnvelopePendingDispositionIsAnError(t *testing.T) {
	const respXML = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <RequestSecurityTokenResponse xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">The request is pending approval.</DispositionMessage>
      <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">5678</RequestID>
    </RequestSecurityTokenResponse>
  </s:Body>
</s:Envelope>`
	_, err := parseResponseEnvelope([]byte(respXML))
	if err == nil {
		t.Fatal("expected an error for a pending disposition with no certificate")
	}
	if !strings.Contains(err.Error(), "pending") {
		t.Errorf("error = %q, want it to mention the pending disposition", err.Error())
	}
}

func TestParseSOAPFaultExtractsReason(t *testing.T) {
	const faultXML = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>s:Sender</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en">Access is denied.</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`
	got := parseSOAPFault([]byte(faultXML))
	if !strings.Contains(got, "Access is denied.") {
		t.Errorf("parseSOAPFault = %q, want it to include the fault reason", got)
	}
}

func TestParseSOAPFaultEmptyForANonFaultBody(t *testing.T) {
	if got := parseSOAPFault([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body></s:Body></s:Envelope>`)); got != "" {
		t.Errorf("parseSOAPFault = %q, want empty for a non-fault body", got)
	}
}

func TestOrderCertificatesFromCSRPutsMatchingLeafFirst(t *testing.T) {
	csrDER, pub := mustGenerateCSR(t, "leaf.example.com")
	leafDER := mustSelfSignedCert(t, "leaf.example.com", pub)
	decoyDER := mustSelfSignedCert(t, "unrelated-intermediate", nil)

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	decoy, err := x509.ParseCertificate(decoyDER)
	if err != nil {
		t.Fatalf("parse decoy: %v", err)
	}

	result := &EnrollResult{Certificates: []*x509.Certificate{decoy, leaf}}
	if err := orderCertificatesFromCSR(result, csrDER); err != nil {
		t.Fatalf("orderCertificatesFromCSR: %v", err)
	}
	if result.Certificates[0].Subject.CommonName != "leaf.example.com" {
		t.Errorf("Certificates[0] = %q, want the certificate matching the CSR's public key first", result.Certificates[0].Subject.CommonName)
	}
}

func TestOrderCertificatesFromCSRErrorsWhenNoCertificateMatches(t *testing.T) {
	csrDER, _ := mustGenerateCSR(t, "leaf.example.com")
	decoyA := mustSelfSignedCert(t, "a", nil)
	decoyB := mustSelfSignedCert(t, "b", nil)
	a, _ := x509.ParseCertificate(decoyA)
	b, _ := x509.ParseCertificate(decoyB)

	result := &EnrollResult{Certificates: []*x509.Certificate{a, b}}
	if err := orderCertificatesFromCSR(result, csrDER); err == nil {
		t.Fatal("expected an error when no returned certificate matches the CSR's public key")
	}
}

// TestHTTPClientEnrollRoundTrip exercises the full Enroll call against a
// real httptest.Server: the server itself decodes the request XML (proving
// it's valid, parseable SOAP) and checks the username/template/CSR made it
// through, then returns a crafted RSTR response for the client to parse.
func TestHTTPClientEnrollRoundTrip(t *testing.T) {
	csrDER, _ := mustGenerateCSR(t, "roundtrip.example.com")
	certDER := mustSelfSignedCert(t, "roundtrip.example.com", nil)
	// Re-parse to get the CSR's own public key for a matching leaf, exactly
	// like a real CA would issue for the key that was actually requested.
	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	certDER = mustSelfSignedCert(t, "roundtrip.example.com", parsedCSR.PublicKey)
	degenerate, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		t.Fatalf("DegenerateCertificate: %v", err)
	}

	var sawUsername, sawTemplate, sawCSRBase64 string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded struct {
			Header struct {
				Security struct {
					UsernameToken struct {
						Username string `xml:"Username"`
					} `xml:"UsernameToken"`
				} `xml:"Security"`
			} `xml:"Header"`
			Body struct {
				RST struct {
					BinarySecurityToken string `xml:"BinarySecurityToken"`
					AdditionalContext   struct {
						ContextItem struct {
							Value string `xml:"Value"`
						} `xml:"ContextItem"`
					} `xml:"AdditionalContext"`
				} `xml:"RequestSecurityToken"`
			} `xml:"Body"`
		}
		if err := xml.Unmarshal(raw, &decoded); err != nil {
			t.Errorf("server received unparseable request XML: %v", err)
		}
		sawUsername = decoded.Header.Security.UsernameToken.Username
		sawTemplate = decoded.Body.RST.AdditionalContext.ContextItem.Value
		sawCSRBase64 = decoded.Body.RST.BinarySecurityToken

		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <RequestSecurityTokenResponse xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">Issued</DispositionMessage>
      <BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS7">%s</BinarySecurityToken>
      <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">42</RequestID>
    </RequestSecurityTokenResponse>
  </s:Body>
</s:Envelope>`, base64.StdEncoding.EncodeToString(degenerate))
	}))
	defer server.Close()

	client := NewHTTPClient(Config{
		Endpoint: server.URL,
		Username: "svc-adcs",
		Password: "secret",
		Template: "WebServer",
	})
	result, err := client.Enroll(context.Background(), csrDER)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if sawUsername != "svc-adcs" {
		t.Errorf("server saw Username = %q, want %q", sawUsername, "svc-adcs")
	}
	if sawTemplate != "WebServer" {
		t.Errorf("server saw template = %q, want %q", sawTemplate, "WebServer")
	}
	if gotCSR, _ := base64.StdEncoding.DecodeString(sawCSRBase64); string(gotCSR) != string(csrDER) {
		t.Error("server did not receive the original CSR bytes")
	}
	if result.RequestID != "42" {
		t.Errorf("RequestID = %q, want %q", result.RequestID, "42")
	}
	if len(result.Certificates) != 1 || result.Certificates[0].Subject.CommonName != "roundtrip.example.com" {
		t.Fatalf("unexpected Certificates: %+v", result.Certificates)
	}
}

func TestHTTPClientEnrollReturnsFaultMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>s:Sender</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en">Access is denied.</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{Endpoint: server.URL, Username: "u", Password: "p", Template: "WebServer"})
	csrDER, _ := mustGenerateCSR(t, "denied.example.com")
	_, err := client.Enroll(context.Background(), csrDER)
	if err == nil {
		t.Fatal("expected an error for a SOAP fault response")
	}
	if !strings.Contains(err.Error(), "Access is denied.") {
		t.Errorf("error = %q, want it to surface the fault reason", err.Error())
	}
}
