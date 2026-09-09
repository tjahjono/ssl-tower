package adcs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.mozilla.org/pkcs7"
)

// requestEnvelopeTemplate builds an MS-WSTEP RequestSecurityToken (RST)
// message wrapping a PKCS#10 request, authenticated via a WS-Security
// UsernameToken — the shape documented in Microsoft's [MS-WSTEP]
// specification for the "Issue" binding. Built via text/template rather
// than encoding/xml struct marshaling: WS-Security's namespace-prefixed,
// attribute-order-sensitive shape is far easier to get byte-for-byte right
// against Microsoft's own published examples this way, and every dynamic
// value is escaped through the xmlesc template func before insertion.
var requestEnvelopeTemplate = template.Must(template.New("wstep-rst").Funcs(template.FuncMap{
	"xmlesc": xmlEscape,
}).Parse(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:{{.MessageID}}</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">{{.Endpoint | xmlesc}}</a:To>
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0">
        <u:Created>{{.Created}}</u:Created>
        <u:Expires>{{.Expires}}</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="uuid-{{.TokenID}}">
        <o:Username>{{.Username | xmlesc}}</o:Username>
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password | xmlesc}}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:TokenType>http://schemas.microsoft.com/windows/pki/2009/01/enrollment</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wst:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#base64binary" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{{.CSRBase64}}</wst:BinarySecurityToken>
      <wst:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <wst:ContextItem Name="CertificateTemplate"><wst:Value>{{.Template | xmlesc}}</wst:Value></wst:ContextItem>
      </wst:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`))

// xmlEscape runs s through encoding/xml's own text escaper — used for every
// dynamic value interpolated into requestEnvelopeTemplate, since a username,
// password, endpoint URL, or template name could in principle contain a
// literal "<"/"&"/etc.
func xmlEscape(s string) string {
	var b bytes.Buffer
	// xml.EscapeText never actually returns an error for well-formed UTF-8
	// input (it only wraps the underlying Writer's own errors, and
	// bytes.Buffer.Write never fails) — ignored deliberately, not
	// overlooked.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func buildRequestEnvelope(cfg Config, csrDER []byte) ([]byte, error) {
	now := time.Now().UTC()
	data := struct {
		MessageID, TokenID                    string
		Endpoint, Username, Password, Template string
		Created, Expires                      string
		CSRBase64                             string
	}{
		MessageID: uuid.NewString(),
		TokenID:   uuid.NewString(),
		Endpoint:  cfg.Endpoint,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Template:  cfg.Template,
		Created:   now.Format("2006-01-02T15:04:05.000Z"),
		Expires:   now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z"),
		CSRBase64: base64.StdEncoding.EncodeToString(csrDER),
	}
	var buf bytes.Buffer
	if err := requestEnvelopeTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- response parsing ----------------------------------------------------

// The structs below deliberately use unqualified (namespace-less) element
// tags: encoding/xml matches an unqualified tag against any element with
// that local name regardless of namespace URI, which is the right kind of
// leniency here — Microsoft's own examples aren't fully consistent about
// which elements sit in the wst/enrollment/no-namespace, and this app has
// no live server to confirm exact namespace usage against (see the package
// doc comment).

type soapResponseEnvelope struct {
	Body soapResponseBody `xml:"Body"`
}

type soapResponseBody struct {
	Fault *soapFault `xml:"Fault"`
	// A response may come back as a bare RequestSecurityTokenResponse or
	// wrapped in a Collection — CES has been observed doing either
	// depending on version, so both are matched and whichever is present
	// wins in parseResponseEnvelope.
	RSTR       *requestSecurityTokenResponse   `xml:"RequestSecurityTokenResponse"`
	Collection *requestSecurityTokenCollection `xml:"RequestSecurityTokenResponseCollection"`
}

type requestSecurityTokenCollection struct {
	Items []requestSecurityTokenResponse `xml:"RequestSecurityTokenResponse"`
}

type requestSecurityTokenResponse struct {
	DispositionMessage  string               `xml:"DispositionMessage"`
	RequestID           string               `xml:"RequestID"`
	BinarySecurityToken binarySecurityToken2 `xml:"BinarySecurityToken"`
}

// binarySecurityToken2 is named to avoid colliding with any future request-
// side type of a similar shape; it only ever appears in a response here.
type binarySecurityToken2 struct {
	ValueType string `xml:"ValueType,attr"`
	Value     string `xml:",chardata"`
}

type soapFault struct {
	// SOAP 1.2 shape.
	Reason string `xml:"Reason>Text"`
	Code   string `xml:"Code>Value"`
	// SOAP 1.1 fallback shape, in case an intermediary (a load balancer, an
	// older IIS/WCF config) downgrades the response.
	FaultString string `xml:"faultstring"`
}

func (f *soapFault) message() string {
	if f == nil {
		return ""
	}
	if f.Reason != "" {
		if f.Code != "" {
			return fmt.Sprintf("%s: %s", f.Code, f.Reason)
		}
		return f.Reason
	}
	return f.FaultString
}

// parseSOAPFault returns a human-readable message if body is a SOAP Fault,
// "" otherwise (including when body isn't parseable XML at all — a
// malformed or truncated fault is reported via the surrounding HTTP-status
// check instead, not silently swallowed).
func parseSOAPFault(body []byte) string {
	var env soapResponseEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return ""
	}
	return env.Body.Fault.message()
}

// parseResponseEnvelope extracts the issued certificate chain from a
// successful RSTR response.
func parseResponseEnvelope(body []byte) (*EnrollResult, error) {
	var env soapResponseEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode SOAP envelope: %w", err)
	}

	rstr := env.Body.RSTR
	if rstr == nil && env.Body.Collection != nil && len(env.Body.Collection.Items) > 0 {
		rstr = &env.Body.Collection.Items[0]
	}
	if rstr == nil {
		return nil, errors.New("response carried no RequestSecurityTokenResponse")
	}

	result := &EnrollResult{
		RequestID:   rstr.RequestID,
		Disposition: strings.TrimSpace(rstr.DispositionMessage),
	}

	raw := strings.TrimSpace(rstr.BinarySecurityToken.Value)
	if raw == "" {
		if result.Disposition != "" {
			return nil, fmt.Errorf("no certificate in response — disposition: %s", result.Disposition)
		}
		return nil, errors.New("no certificate in response")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode BinarySecurityToken base64: %w", err)
	}

	certs, err := decodeCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("decode issued certificate: %w", err)
	}
	result.Certificates = certs
	return result, nil
}

// decodeCertificates handles both shapes ADCS is documented to return: a
// PKCS#7 "degenerate" SignedData (certificates only, no actual signature —
// the common case) or, less commonly, a single raw DER certificate.
func decodeCertificates(der []byte) ([]*x509.Certificate, error) {
	if p7, err := pkcs7.Parse(der); err == nil && len(p7.Certificates) > 0 {
		return p7.Certificates, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("neither PKCS#7 nor a raw certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

// orderCertificatesFromCSR reorders result.Certificates so the leaf (the
// certificate whose public key matches the original request) is first,
// followed by the rest in whatever order they arrived. A PKCS#7 "degenerate"
// certs-only structure is an unordered ASN.1 SET — nothing guarantees the
// issued leaf is Certificates[0] the way it would be for a normal signed
// PKCS#7 — so this is correctness, not a formatting nicety.
func orderCertificatesFromCSR(result *EnrollResult, csrDER []byte) error {
	if len(result.Certificates) <= 1 {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("parse original CSR to identify the issued leaf: %w", err)
	}
	for i, cert := range result.Certificates {
		if publicKeyEqual(cert.PublicKey, csr.PublicKey) {
			if i != 0 {
				result.Certificates[0], result.Certificates[i] = result.Certificates[i], result.Certificates[0]
			}
			return nil
		}
	}
	return errors.New("issued certificate chain contains no certificate matching the request's public key")
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		return ok && ak.Equal(bk)
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		return ok && ak.Equal(bk)
	default:
		return false
	}
}
