-- v1.3: DigiCert renewal integration (Phase 6). Admin-triggered only — a
-- ticket is submitted to DigiCert one at a time via an explicit click, never
-- automatically on approval or by the auto-draft sweeper — see
-- internal/pkg/digicert and CertificateRequestService/DigiCertService.

-- digicert_order_id is set once a certificate has actually been ordered
-- through this integration, so a later renewal of that same certificate can
-- use DigiCert's faster reissue path instead of placing a brand-new order.
-- Empty for every certificate obtained any other way.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS digicert_order_id TEXT NOT NULL DEFAULT '';

-- The four columns below track a ticket's external-CA submission, kept
-- separate from the existing manual-paste fulfillment fields
-- (result_certificate_id, fulfilled_by, fulfilled_at) so the manual paste
-- flow (FulfillExternal) stays completely untouched as a fallback for
-- non-DigiCert CAs or a failed integration call.
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS external_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS external_order_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS external_order_status TEXT NOT NULL DEFAULT '';
-- pending_certificate_id points at the vault record DigiCertService.Submit
-- creates to hold the fresh key pair + CSR sent to DigiCert, before the
-- order is issued. ON DELETE SET NULL mirrors existing_certificate_id and
-- result_certificate_id above — deleting a certificate never cascades into
-- deleting ticket history.
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS pending_certificate_id UUID REFERENCES certificates (id) ON DELETE SET NULL;
