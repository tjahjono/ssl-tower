-- v1.3: auto-drafted renewal tickets. A background sweeper (mirroring the
-- existing alert sweeper's periodic-scan shape) proactively drafts a pending
-- renewal ticket for an internal certificate approaching expiry, on behalf
-- of whoever originally requested it — see
-- CertificateRequestService.AutoDraftRenewals. auto_generated distinguishes
-- a system-drafted ticket from one a requester actually typed, purely for
-- display (a badge on the ticket queue/detail) — it carries no other
-- behavioral difference: an auto-drafted ticket is approved, rejected, or
-- fulfilled exactly like any other.
--
-- No new column links a certificate back to the ticket that produced it —
-- certificate_requests.result_certificate_id (added in 0010) already does
-- that in reverse, and the sweeper just queries it
-- (WHERE result_certificate_id = <certificate id>) to find a certificate's
-- origin ticket/requester. A certificate with no such ticket (created
-- directly in the vault, say) has no resolvable requester and is silently
-- skipped by the sweeper.
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS auto_generated BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS certificate_requests_result_certificate_idx ON certificate_requests (result_certificate_id);
