-- v1.4: LDAP authentication support. Every account keeps its existing
-- password_hash column regardless of source — an LDAP-provisioned account
-- gets an unusable random hash there (see authcrypto usage in
-- AuthService's ldapLogin) since it is NOT NULL and this app never needs a
-- separate nullable column to mean "no local password" when "a password
-- that can never match" already does the job with no schema branching
-- elsewhere.
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_auth_source_check;

DO $$ BEGIN
    ALTER TABLE users ADD CONSTRAINT users_auth_source_check
        CHECK (auth_source IN ('local', 'ldap'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
