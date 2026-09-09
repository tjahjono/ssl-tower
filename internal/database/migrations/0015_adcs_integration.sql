-- ADCS (Active Directory Certificate Services) CES/CEP integration — a third
-- "sign with" option on the pending-certificate detail page, alongside
-- self-sign and an uploaded/generated Root CA. See internal/pkg/adcs and
-- CertificateService.SignWithADCS.

-- signed_by_adcs marks a certificate as internally issued via ADCS, the
-- same trust-class role signed_by_root_ca_id plays for an in-app Root CA —
-- there is no in-app CA record to reference here, ADCS's own CA lives
-- entirely outside this app, so a plain boolean rather than a foreign key.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS signed_by_adcs BOOLEAN NOT NULL DEFAULT false;

-- adcs_request_id is purely informational — the request/serial ID ADCS's
-- RSTR response reported, for looking the request up on the CA server.
-- Never used to decide trust class; may be empty even when signed_by_adcs
-- is true if the server's response didn't carry one.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS adcs_request_id TEXT NOT NULL DEFAULT '';
