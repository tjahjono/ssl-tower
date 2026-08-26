package http

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/service"
)

// --- requester-facing pages --------------------------------------------

// handleRequestsPage renders the self-service "my requests" workspace: the
// submission form plus every ticket in the system — visibility is
// deliberately "all tickets", not just the signed-in requester's own, per
// the confirmed workflow decision.
func (s *Server) handleRequestsPage(w http.ResponseWriter, r *http.Request) {
	tickets, err := s.requests.List(r.Context(), domain.CertificateRequestFilter{})
	if err != nil {
		s.serverError(w, err)
		return
	}
	renewable, err := s.certs.List(r.Context(), domain.CertificateFilter{Status: domain.CertIssued})
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "My requests", "requests")
	view["Tickets"] = tickets
	view["RenewableCertificates"] = renewable
	view["SLADays"] = s.requests.SLADays()
	s.render.Page(w, http.StatusOK, "requests", view)
}

// handleRequestsList returns just the ticket table, for htmx polling/refresh.
func (s *Server) handleRequestsList(w http.ResponseWriter, r *http.Request) {
	tickets, err := s.requests.List(r.Context(), domain.CertificateRequestFilter{})
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Tickets"] = tickets
	view["SLADays"] = s.requests.SLADays()
	s.render.Partial(w, http.StatusOK, "request-table", view)
}

// handleRequestSubmit files a new certificate request ticket.
func (s *Server) handleRequestSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	user := s.currentUser(r)

	in := service.SubmitInput{
		RequesterID:    user.ID,
		RequesterEmail: user.Email,
		Type:           domain.RequestType(r.PostFormValue("type")),
		TrustClass:     domain.CertTrustClass(r.PostFormValue("trust_class")),
		CommonName:     r.PostFormValue("common_name"),
		SANs:           r.PostFormValue("sans"),
		Organization:   r.PostFormValue("organization"),
		Owner:          r.PostFormValue("owner"),
		Justification:  r.PostFormValue("justification"),
		PONumber:       r.PostFormValue("po_number"),
	}
	if raw := r.PostFormValue("existing_certificate_id"); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			in.ExistingCertificateID = &id
		}
	}

	ticket, err := s.requests.Submit(r.Context(), in)
	if err != nil {
		msg, _ := errorMessage(err)
		s.requestTableResponse(w, r, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestSubmitted, "certificate_request", ticket.ID.String(), ticket.CommonName)
	s.requestTableResponse(w, r, &flashMessage{Kind: "success", Message: "Request submitted — an editor or admin will review it shortly."})
}

// handleRequestCancel cancels an open ticket. Reachable from both /requests
// (a requester cancelling their own submission) and /tickets (an
// editor/admin cancelling on the requester's behalf) — a plain requester may
// only cancel a ticket they themselves filed.
func (s *Server) handleRequestCancel(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	user := s.currentUser(r)
	if !user.Role.CanWrite() {
		ticket, err := s.requests.Get(r.Context(), id)
		if err != nil {
			s.notFoundOr(w, err)
			return
		}
		if ticket.RequesterID != user.ID {
			s.forbidden(w, r)
			return
		}
	}

	ticket, err := s.requests.Cancel(r.Context(), service.CancelInput{TicketID: id, ActorID: user.ID})
	if err != nil {
		msg, _ := errorMessage(err)
		if user.Role.CanWrite() {
			s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		} else {
			s.requestTableResponse(w, r, &flashMessage{Kind: "error", Message: msg})
		}
		return
	}
	s.recordAudit(r, domain.AuditRequestCancelled, "certificate_request", ticket.ID.String(), ticket.CommonName)
	if user.Role.CanWrite() {
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "info", Message: "Ticket cancelled."})
		return
	}
	s.requestTableResponse(w, r, &flashMessage{Kind: "info", Message: "Request cancelled."})
}

// --- editor/admin ticket queue ------------------------------------------

// handleTicketsPage renders the ticket queue.
func (s *Server) handleTicketsPage(w http.ResponseWriter, r *http.Request) {
	filter := ticketFilterFrom(r)
	tickets, err := s.requests.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	open, err := s.requests.CountOpen(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Tickets", "tickets")
	view["Tickets"] = tickets
	view["Filter"] = filter
	view["OpenCount"] = open
	view["SLADays"] = s.requests.SLADays()
	s.render.Page(w, http.StatusOK, "tickets", view)
}

// handleTicketsList returns just the ticket table, for search/polling.
func (s *Server) handleTicketsList(w http.ResponseWriter, r *http.Request) {
	filter := ticketFilterFrom(r)
	tickets, err := s.requests.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Tickets"] = tickets
	view["Filter"] = filter
	view["SLADays"] = s.requests.SLADays()
	s.render.Partial(w, http.StatusOK, "ticket-table", view)
}

// handleTicketDetail renders one ticket, with whichever action forms its
// current status and trust class allow — the embedded certificate
// generate/attach/sign forms scoped to this ticket (Option A: approving and
// creating the certificate happen as one action).
func (s *Server) handleTicketDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	view := newView(r, "Ticket", "tickets")
	if !s.decorateTicketView(r, view, id) {
		s.notFoundOr(w, domain.ErrNotFound)
		return
	}
	s.render.Page(w, http.StatusOK, "ticket_detail", view)
}

// handleTicketApproveInternal approves an internal ticket and signs its
// certificate with a Root CA in the same action.
func (s *Server) handleTicketApproveInternal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	rootCAID, err := uuid.Parse(r.PostFormValue("root_ca_id"))
	if err != nil {
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: "choose a Root CA to sign with"})
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	if days <= 0 {
		days = 365
	}
	bits, _ := strconv.Atoi(r.PostFormValue("key_bits"))

	ticket, cert, err := s.requests.ApproveInternal(r.Context(), service.ApproveInternalInput{
		TicketID:   id,
		ApproverID: s.currentUser(r).ID,
		CSR: service.CreateCSRInput{
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
			Notes:              "Fulfills certificate request ticket",
		},
		RootCAID: rootCAID,
		Days:     days,
	})
	if err != nil {
		msg, _ := errorMessage(err)
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestApproved, "certificate_request", ticket.ID.String(), ticket.CommonName)
	s.recordAudit(r, domain.AuditRequestFulfilled, "certificate_request", ticket.ID.String(), cert.CommonName)
	s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "success", Message: "Approved and signed — deliver the certificate to the requester by hand."})
}

// handleTicketApproveExternal approves an external ticket, moving it to
// in-progress while procurement happens manually outside the app.
func (s *Server) handleTicketApproveExternal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ticket, err := s.requests.ApproveExternal(r.Context(), service.ApproveExternalInput{
		TicketID:   id,
		ApproverID: s.currentUser(r).ID,
	})
	if err != nil {
		msg, _ := errorMessage(err)
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestApproved, "certificate_request", ticket.ID.String(), ticket.CommonName)
	s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "success", Message: "Approved — now in progress with the external CA."})
}

// handleTicketFulfillExternal attaches the certificate a public CA issued,
// closing out an in-progress external ticket.
func (s *Server) handleTicketFulfillExternal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	ticket, cert, err := s.requests.FulfillExternal(r.Context(), service.FulfillExternalInput{
		TicketID:   id,
		ApproverID: s.currentUser(r).ID,
		Import: service.ImportInput{
			CertificatePEM: r.PostFormValue("certificate_pem"),
			ChainPEM:       r.PostFormValue("chain_pem"),
			PrivateKeyPEM:  r.PostFormValue("private_key_pem"),
			Notes:          "Fulfills certificate request ticket",
		},
	})
	if err != nil {
		msg, _ := errorMessage(err)
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestFulfilled, "certificate_request", ticket.ID.String(), cert.CommonName)
	s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "success", Message: "Certificate attached — ticket fulfilled. Deliver it to the requester by hand."})
}

// handleTicketReject rejects a pending ticket with a reason.
func (s *Server) handleTicketReject(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	ticket, err := s.requests.Reject(r.Context(), service.RejectInput{
		TicketID: id,
		ActorID:  s.currentUser(r).ID,
		Reason:   r.PostFormValue("reason"),
	})
	if err != nil {
		msg, _ := errorMessage(err)
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestRejected, "certificate_request", ticket.ID.String(), ticket.RejectionReason)
	s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "info", Message: "Ticket rejected."})
}

// handleTicketDeliver records that the fulfilled certificate has been
// handed to the requester by hand.
func (s *Server) handleTicketDeliver(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ticket, err := s.requests.Deliver(r.Context(), service.DeliverInput{
		TicketID: id,
		ActorID:  s.currentUser(r).ID,
	})
	if err != nil {
		msg, _ := errorMessage(err)
		s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "error", Message: msg})
		return
	}
	s.recordAudit(r, domain.AuditRequestDelivered, "certificate_request", ticket.ID.String(), ticket.CommonName)
	s.ticketDetailResponse(w, r, id, &flashMessage{Kind: "success", Message: "Marked delivered."})
}

// --- shared helpers -------------------------------------------------------

func ticketFilterFrom(r *http.Request) domain.CertificateRequestFilter {
	q := r.URL.Query()
	return domain.CertificateRequestFilter{
		Search:     q.Get("q"),
		Status:     domain.RequestStatus(q.Get("status")),
		TrustClass: domain.CertTrustClass(q.Get("trust")),
	}
}

// decorateTicketView loads a ticket and everything its detail page needs to
// render — the linked certificate/requester context, and, for a pending
// ticket, the Root CA list the internal approval form offers. Returns false
// when the ticket doesn't exist.
func (s *Server) decorateTicketView(r *http.Request, view map[string]any, id uuid.UUID) bool {
	ticket, err := s.requests.Get(r.Context(), id)
	if err != nil {
		return false
	}
	view["Ticket"] = ticket
	view["SLADays"] = s.requests.SLADays()

	if ticket.ExistingCertificateID != nil {
		if existing, err := s.certs.Get(r.Context(), *ticket.ExistingCertificateID); err == nil {
			view["ExistingCertificate"] = existing
		}
	}
	if ticket.ResultCertificateID != nil {
		if result, err := s.certs.Get(r.Context(), *ticket.ResultCertificateID); err == nil {
			view["ResultCertificate"] = result
			// Lets the ticket detail page offer a direct download of the
			// fulfilled certificate, instead of making the admin click
			// through to the certificate vault to get it. Same role gate
			// as the certificate detail page: only an admin can download
			// certificates/key material, an editor can still export a bare
			// CSR (moot here since a fulfilled ticket's result always has
			// an issued certificate, but kept consistent).
			view["ResultFormats"] = certificateFormats(result)
			view["CanDownloadResult"] = s.currentUser(r).Role.CanManageUsers()
			view["CanExportResultCSR"] = s.currentUser(r).Role.CanWrite()
		}
	}
	if ticket.Status == domain.RequestPending && ticket.TrustClass == domain.TrustInternal {
		if rootCAs, err := s.certs.ListRootCAs(r.Context()); err == nil {
			view["RootCAs"] = rootCAs
		}
	}
	return true
}

func (s *Server) ticketDetailResponse(w http.ResponseWriter, r *http.Request, id uuid.UUID, flash *flashMessage) {
	view := newView(r, "", "")
	if !s.decorateTicketView(r, view, id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	view["Flash"] = flash
	s.render.Partial(w, http.StatusOK, "ticket-detail-response", view)
}

func (s *Server) requestTableResponse(w http.ResponseWriter, r *http.Request, flash *flashMessage) {
	tickets, err := s.requests.List(r.Context(), domain.CertificateRequestFilter{})
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Tickets"] = tickets
	view["SLADays"] = s.requests.SLADays()
	view["Flash"] = flash
	s.render.Partial(w, http.StatusOK, "request-table-response", view)
}
