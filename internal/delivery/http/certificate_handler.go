package http

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
	"github.com/ivangiovn/ssl-generator/internal/service"
)

// maxUploadBytes bounds a single multipart upload (bulk PFX import) — plenty
// for a batch of certificate bundles, not enough to be a memory-exhaustion vector.
const maxUploadBytes = 32 << 20 // 32 MiB

// handleDashboard renders the overview: status tiles, anything needing
// attention, the full certificate list, and which CAs the fleet depends on.
// It is one of the two pages reachable without a session (Help is the
// other), and by explicit request the certificate list and CA breakdown are
// public and read-only here — no key material, no CSR text, and no
// create/attach/delete affordances are shown to an anonymous visitor;
// clicking through to a detail page still requires signing in.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	summary, err := s.certs.Summary(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	certs, err := s.certs.List(ctx, domain.CertificateFilter{})
	if err != nil {
		s.serverError(w, err)
		return
	}
	warning, critical := s.certs.Thresholds()

	attention := make([]*domain.Certificate, 0, len(certs))
	for _, c := range certs {
		if c.Status == domain.CertIssued && c.HealthStatus(warning, critical) != domain.StatusOK {
			attention = append(attention, c)
		}
	}

	view := newView(r, "Dashboard", "dashboard")
	view["Summary"] = summary
	view["Attention"] = attention
	view["Certificates"] = certs
	view["Groups"] = service.GroupByIssuer(certs)
	view["WarningDays"] = warning
	view["CriticalDays"] = critical
	view["LastSweep"] = s.sweeper.LastRun()
	view["SweepInterval"] = humanDuration(s.sweeper.Interval())
	s.render.Page(w, http.StatusOK, "dashboard", view)
}

// handleSummaryPartial refreshes the dashboard tiles for htmx polling.
func (s *Server) handleSummaryPartial(w http.ResponseWriter, r *http.Request) {
	summary, err := s.certs.Summary(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Summary"] = summary
	view["LastSweep"] = s.sweeper.LastRun()
	s.render.Partial(w, http.StatusOK, "summary-tiles", view)
}

// handleCertificatesPage renders the certificate vault workspace.
func (s *Server) handleCertificatesPage(w http.ResponseWriter, r *http.Request) {
	filter := certificateFilterFrom(r)
	certs, err := s.certs.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	warning, critical := s.certs.Thresholds()

	view := newView(r, "Certificates", "certificates")
	view["Certificates"] = certs
	view["Filter"] = filter
	view["Encrypted"] = s.certs.KeyEncryptionEnabled()
	view["WarningDays"] = warning
	view["CriticalDays"] = critical
	view["CanDownload"] = s.currentUser(r).Role.CanManageUsers()
	view["EKUOptions"] = certutil.ExtKeyUsageOptions()
	s.render.Page(w, http.StatusOK, "certificates", view)
}

// handleCertificateList returns just the table, for search and polling.
func (s *Server) handleCertificateList(w http.ResponseWriter, r *http.Request) {
	filter := certificateFilterFrom(r)
	certs, err := s.certs.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	warning, critical := s.certs.Thresholds()
	view := newView(r, "", "")
	view["Certificates"] = certs
	view["Filter"] = filter
	view["WarningDays"] = warning
	view["CriticalDays"] = critical
	s.render.Partial(w, http.StatusOK, "certificate-table", view)
}

// handleCertificateIssuers groups issued certificates by issuing CA — which
// certificate authorities the fleet depends on, and how concentrated that
// dependency is.
func (s *Server) handleCertificateIssuers(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certs.List(r.Context(), domain.CertificateFilter{})
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Issuers", "issuers")
	view["Groups"] = service.GroupByIssuer(certs)
	view["Total"] = len(certs)
	s.render.Page(w, http.StatusOK, "certificate_issuers", view)
}

// handleCertificateGenerate mints a key pair plus CSR and sends the user to
// its detail page.
func (s *Server) handleCertificateGenerate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	bits, _ := strconv.Atoi(r.PostFormValue("key_bits"))
	selfSignDays := 0
	if r.PostFormValue("self_sign") == "on" {
		selfSignDays, _ = strconv.Atoi(r.PostFormValue("self_sign_days"))
		if selfSignDays <= 0 {
			selfSignDays = 365
		}
	}

	in := service.CreateCSRInput{
		CommonName:         r.PostFormValue("common_name"),
		Organization:       r.PostFormValue("organization"),
		OrganizationalUnit: r.PostFormValue("organizational_unit"),
		Country:            r.PostFormValue("country"),
		Province:           r.PostFormValue("province"),
		Locality:           r.PostFormValue("locality"),
		Email:              r.PostFormValue("email"),
		SANs:               r.PostFormValue("sans"),
		KeyAlgorithm:       r.PostFormValue("key_algorithm"),
		KeyBits:            bits,
		KeyCurve:           r.PostFormValue("key_curve"),
		Owner:              r.PostFormValue("owner"),
		Notes:              r.PostFormValue("notes"),
		SelfSignDays:       selfSignDays,
		ExtKeyUsages:       r.PostForm["eku"],
	}

	record, err := s.certs.CreateCSR(r.Context(), in)
	if err != nil {
		msg, _ := errorMessage(err)
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditCertificateCreated, "certificate", record.ID.String(), record.CommonName)
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/certificates/"+record.ID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/certificates/"+record.ID.String(), http.StatusSeeOther)
}

// handleCertificateImport stores a certificate uploaded as PEM.
func (s *Server) handleCertificateImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	in := service.ImportInput{
		CertificatePEM: r.PostFormValue("certificate_pem"),
		ChainPEM:       r.PostFormValue("chain_pem"),
		PrivateKeyPEM:  r.PostFormValue("private_key_pem"),
		Owner:          r.PostFormValue("owner"),
		Notes:          r.PostFormValue("notes"),
	}
	record, err := s.certs.Import(r.Context(), in)
	if err != nil {
		msg, _ := errorMessage(err)
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditCertificateImported, "certificate", record.ID.String(), record.CommonName)
	s.certificateImportedResponse(w, r, record)
}

// handleCertificateImportCSR stores a CSR and matching private key generated
// elsewhere (e.g. on an operator's own laptop with openssl) as a pending
// certificate, ready for the same attach/self-sign flow as a CSR this app
// generated itself.
func (s *Server) handleCertificateImportCSR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	in := service.ImportCSRInput{
		CSRPEM:        r.PostFormValue("csr_pem"),
		PrivateKeyPEM: r.PostFormValue("private_key_pem"),
		Owner:         r.PostFormValue("owner"),
		Notes:         r.PostFormValue("notes"),
	}
	record, err := s.certs.ImportCSR(r.Context(), in)
	if err != nil {
		msg, _ := errorMessage(err)
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditCertificateCSRImported, "certificate", record.ID.String(), record.CommonName)
	s.certificateImportedResponse(w, r, record)
}

// handleCertificateImportPFX imports one or more PKCS#12 (.pfx/.p12) bundles
// in a single request — the bulk-import path. The same password is tried
// against every file.
func (s *Server) handleCertificateImportPFX(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: "The upload was too large or malformed."})
		return
	}
	headers := r.MultipartForm.File["pfx_files"]
	if len(headers) == 0 {
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: "Choose at least one .pfx/.p12 file."})
		return
	}

	password := r.PostFormValue("password")
	owner := r.PostFormValue("owner")
	notes := r.PostFormValue("notes")

	files := make(map[string][]byte, len(headers))
	for _, fh := range headers {
		f, err := fh.Open()
		if err != nil {
			s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: "Could not read " + fh.Filename + "."})
			return
		}
		data, err := io.ReadAll(io.LimitReader(f, maxUploadBytes))
		f.Close()
		if err != nil {
			s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: "Could not read " + fh.Filename + "."})
			return
		}
		files[fh.Filename] = data
	}

	results := s.certs.BulkImportPFX(r.Context(), files, password, owner, notes)
	ok, failed := 0, 0
	var lastID string
	for _, res := range results {
		if res.Err != nil {
			failed++
			s.log.Warn("pfx import failed", "file", res.Filename, "error", res.Err)
			continue
		}
		ok++
		lastID = res.Certificate.ID.String()
		s.recordAudit(r, domain.AuditCertificateImported, "certificate", res.Certificate.ID.String(), res.Filename)
	}

	switch {
	case ok == 1 && failed == 0:
		if rec, err := s.certs.Get(r.Context(), uuid.MustParse(lastID)); err == nil {
			s.certificateImportedResponse(w, r, rec)
			return
		}
		fallthrough
	case failed == 0:
		s.certificateTableResponse(w, r, &flashMessage{Kind: "success", Message: fmt.Sprintf("Imported %d certificates.", ok)})
	case ok == 0:
		s.certificateTableResponse(w, r, &flashMessage{Kind: "error", Message: fmt.Sprintf("All %d file(s) failed to import — check the password and try again.", failed)})
	default:
		s.certificateTableResponse(w, r, &flashMessage{Kind: "warning", Message: fmt.Sprintf("Imported %d of %d files — %d failed. Check the server log for details.", ok, ok+failed, failed)})
	}
}

// certificateImportedResponse sends a freshly imported/generated certificate
// straight to its detail page (address-bar navigation) or via HX-Redirect
// (htmx), matching the CSR-create flow's existing behaviour.
func (s *Server) certificateImportedResponse(w http.ResponseWriter, r *http.Request, record *domain.Certificate) {
	dest := "/certificates/" + record.ID.String()
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", dest)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleCertificateDetail renders one certificate with its download options.
func (s *Server) handleCertificateDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	record, err := s.certs.Get(r.Context(), id)
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	view := newView(r, record.CommonName, "certificates")
	s.decorateCertificateView(r, view, record)
	s.render.Page(w, http.StatusOK, "certificate_detail", view)
}

// handleCertificateAttach stores the certificate the CA issued for a pending request.
func (s *Server) handleCertificateAttach(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	blob := r.PostFormValue("certificate_pem")
	if strings.TrimSpace(blob) == "" {
		s.certificateDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: "Paste the PEM certificate returned by your CA."})
		return
	}
	record, err := s.certs.AttachCertificate(r.Context(), id, blob)
	if err != nil {
		msg, _ := errorMessage(err)
		s.certificateDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditCertificateAttached, "certificate", record.ID.String(), record.CommonName)
	view := newView(r, "", "")
	s.decorateCertificateView(r, view, record)
	view["Flash"] = &flashMessage{
		Kind:    "success",
		Message: fmt.Sprintf("Certificate attached, valid until %s.", record.NotAfter.UTC().Format("2 Jan 2006")),
	}
	s.render.Partial(w, http.StatusOK, "certificate-detail-response", view)
}

// handleCertificateSelfSign issues a self-signed certificate for a pending request.
func (s *Server) handleCertificateSelfSign(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	if days <= 0 {
		days = 365
	}
	record, err := s.certs.SelfSign(r.Context(), id, days)
	if err != nil {
		msg, _ := errorMessage(err)
		s.certificateDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditCertificateSelfSigned, "certificate", record.ID.String(), fmt.Sprintf("%d days", days))
	view := newView(r, "", "")
	s.decorateCertificateView(r, view, record)
	view["Flash"] = &flashMessage{
		Kind:    "success",
		Message: fmt.Sprintf("Self-signed certificate issued for %d days. Browsers will not trust it — use it for staging only.", days),
	}
	s.render.Partial(w, http.StatusOK, "certificate-detail-response", view)
}

// handleCertificateDelete removes a certificate and its key material.
func (s *Server) handleCertificateDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := s.certs.Delete(r.Context(), id); err != nil {
		s.notFoundOr(w, err)
		return
	}
	s.recordAudit(r, domain.AuditCertificateDeleted, "certificate", id.String(), "")
	if r.URL.Query().Get("redirect") == "list" {
		w.Header().Set("HX-Redirect", "/certificates")
		w.WriteHeader(http.StatusOK)
		return
	}
	s.certificateTableResponse(w, r, &flashMessage{Kind: "info", Message: "Certificate deleted."})
}

// handleCertificateDownload serves the requested artefact. Every download
// needs a session; only an admin can download anything that carries — or
// could carry — key material. The one carve-out, per the certificate vault's
// access-control decision: an editor may still export the bare signing
// request text (no key involved) to send to a CA themselves.
func (s *Server) handleCertificateDownload(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	format := q.Get("format")
	user := s.currentUser(r)

	allowed := user.Role.CanManageUsers()
	if !allowed && format == certutil.FormatCSR {
		allowed = user.Role.CanWrite()
	}
	if !allowed {
		http.Error(w, "only an admin can download this — editors may still export the bare signing request", http.StatusForbidden)
		return
	}

	result, err := s.certs.Export(r.Context(), id, service.ExportOptions{
		Format:      format,
		PFXPassword: q.Get("password"),
		PFXLegacy:   q.Get("legacy") == "on",
	})
	if err != nil {
		msg, status := errorMessage(err)
		if status == http.StatusInternalServerError {
			msg = err.Error()
			status = http.StatusBadRequest
		}
		http.Error(w, msg, status)
		return
	}
	if formatIncludesPrivateKey(format) {
		s.recordAudit(r, domain.AuditKeyDownloaded, "certificate", id.String(), format)
	}
	serveDownload(w, result)
}

// --- helpers ---------------------------------------------------------------

// formatIncludesPrivateKey reports whether an export format hands over the
// private key material — the trigger for a private-key-download audit entry.
func formatIncludesPrivateKey(format string) bool {
	switch format {
	case certutil.FormatKEY, certutil.FormatPFX, certutil.FormatZIP:
		return true
	default:
		return false
	}
}

func certificateFilterFrom(r *http.Request) domain.CertificateFilter {
	q := r.URL.Query()
	return domain.CertificateFilter{
		Search: q.Get("q"),
		Status: domain.CertLifecycle(q.Get("status")),
		Origin: domain.CertOrigin(q.Get("origin")),
	}
}

// decorateCertificateView adds the derived data the detail templates need.
func (s *Server) decorateCertificateView(r *http.Request, view map[string]any, record *domain.Certificate) {
	view["Certificate"] = record
	view["Encrypted"] = s.certs.KeyEncryptionEnabled()
	view["Formats"] = certificateFormats(record)
	view["CanDownload"] = s.currentUser(r).Role.CanManageUsers()
	view["CanExportCSR"] = s.currentUser(r).Role.CanWrite()
	warning, critical := s.certs.Thresholds()
	view["Health"] = record.HealthFindings()
	view["HealthStatus"] = record.HealthStatus(warning, critical)
	if shared, err := s.certs.SharedFingerprint(r.Context(), record); err == nil {
		view["SharedWith"] = shared
	}
}

func (s *Server) certificateDetailResponse(w http.ResponseWriter, r *http.Request, id uuid.UUID, flash *flashMessage) {
	record, err := s.certs.Get(r.Context(), id)
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	view := newView(r, "", "")
	s.decorateCertificateView(r, view, record)
	view["Flash"] = flash
	s.render.Partial(w, http.StatusOK, "certificate-detail-response", view)
}

func (s *Server) certificateTableResponse(w http.ResponseWriter, r *http.Request, flash *flashMessage) {
	filter := certificateFilterFrom(r)
	certs, err := s.certs.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	warning, critical := s.certs.Thresholds()
	view := newView(r, "", "")
	view["Certificates"] = certs
	view["Filter"] = filter
	view["WarningDays"] = warning
	view["CriticalDays"] = critical
	view["Flash"] = flash
	s.render.Partial(w, http.StatusOK, "certificate-table-response", view)
}

// certificateFormats lists the downloads that make sense for the
// certificate's current state — unavailable when there's no private key to
// pair with a format that needs one.
func certificateFormats(record *domain.Certificate) []downloadFormat {
	var formats []downloadFormat
	if strings.TrimSpace(record.CSRPEM) != "" {
		formats = append(formats, downloadFormat{Value: certutil.FormatCSR, Label: "Signing request (.csr)", Hint: "send this to your CA"})
	}
	if record.HasPrivateKey() {
		formats = append(formats, downloadFormat{Value: certutil.FormatKEY, Label: "Private key (.key)", Hint: "PKCS#8 PEM — keep it secret"})
	}
	if record.HasCertificate() {
		formats = append(formats,
			downloadFormat{Value: certutil.FormatPEM, Label: "Full chain (.pem)", Hint: "nginx, Apache, HAProxy"},
			downloadFormat{Value: certutil.FormatCRT, Label: "Certificate (.crt)", Hint: "leaf only, PEM"},
			downloadFormat{Value: certutil.FormatDER, Label: "DER (.der / .cer)", Hint: "binary, Java & Windows"},
			downloadFormat{Value: certutil.FormatP7B, Label: "PKCS#7 (.p7b)", Hint: "Windows / IIS chain"},
		)
		if record.HasPrivateKey() {
			formats = append(formats, downloadFormat{Value: certutil.FormatPFX, Label: "PKCS#12 (.pfx / .p12)", Hint: "IIS, Azure, Java — key included"})
		} else {
			formats = append(formats, downloadFormat{Value: certutil.FormatPFX, Label: "PKCS#12 trust store (.pfx)", Hint: "certificates only, no key on file"})
		}
	}
	if len(formats) > 0 {
		formats = append(formats, downloadFormat{Value: certutil.FormatZIP, Label: "Everything (.zip)", Hint: "whatever is on file, every format"})
	}
	return formats
}

// --- generic response helpers shared by every handler file -----------------

type downloadFormat struct {
	Value string
	Label string
	Hint  string
}

// humanDuration renders 12h0m0s as "12 hours" and 15m0s as "15 minutes".
func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute")
	default:
		return d.String()
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func serveDownload(w http.ResponseWriter, result *certutil.ExportResult) {
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", result.Filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Data)
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "error", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (s *Server) notFoundOr(w http.ResponseWriter, err error) {
	msg, status := errorMessage(err)
	if status == http.StatusInternalServerError {
		s.serverError(w, err)
		return
	}
	http.Error(w, msg, status)
}
