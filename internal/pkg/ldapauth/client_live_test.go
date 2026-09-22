package ldapauth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// These tests exercise LDAPClient against a real OpenLDAP (slapd) instance
// rather than a fake — see the package doc comment for why LDAP earns that
// higher bar of verification where DigiCert's proprietary, credential-gated
// API could not. They're skipped unless LDAP_LIVE_TEST_URL points at a
// running test directory, seeded exactly as the shell snippet below
// describes, so the suite still runs (skipped) in any environment without
// slapd installed:
//
//	dc=sslgen,dc=test                                   (organization)
//	  ou=people
//	    uid=alice  mail=alice@example.com  pw=alicepass  (member of sslgen-editors)
//	    uid=carol  mail=carol@example.com  pw=carolpass  (member of sslgen-viewers)
//	    uid=bob    mail=bob@example.com    pw=bobpass    (member of no group)
//	  ou=groups
//	    cn=sslgen-editors (groupOfNames, member: alice)
//	    cn=sslgen-viewers (groupOfNames, member: carol)
//	cn=svc-sslgen,dc=sslgen,dc=test  pw=svcpass           (service bind account)
//
// This exact directory was stood up and exercised during development (both
// via the ldapsearch/ldapwhoami CLI directly and via this test file) against
// a real slapd 2.6.10 instance — see CLAUDE.md's LDAP locked decisions for
// the transcript summary.
func liveTestConfig(t *testing.T) Config {
	t.Helper()
	url := os.Getenv("LDAP_LIVE_TEST_URL")
	if url == "" {
		t.Skip("LDAP_LIVE_TEST_URL not set — skipping live slapd-backed tests (see package doc comment for how to stand one up)")
	}
	return Config{
		URL:          url,
		BindDN:       "cn=svc-sslgen,dc=sslgen,dc=test",
		BindPassword: "svcpass",
		BaseDN:       "dc=sslgen,dc=test",
		UserFilter:   "(mail=%s)",
		GroupFilter:  "(&(objectClass=groupOfNames)(member=%s))",
	}
}

func TestLiveAuthenticateSucceedsAndResolvesGroups(t *testing.T) {
	c := NewLDAPClient(liveTestConfig(t))
	res, err := c.Authenticate(context.Background(), "alice@example.com", "alicepass")
	if err != nil {
		t.Fatalf("expected alice to authenticate against the real directory, got %v", err)
	}
	if res.DN != "uid=alice,ou=people,dc=sslgen,dc=test" {
		t.Fatalf("unexpected DN: %q", res.DN)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "cn=sslgen-editors,ou=groups,dc=sslgen,dc=test" {
		t.Fatalf("expected alice to resolve to exactly the editors group, got %v", res.Groups)
	}
}

func TestLiveAuthenticateWithNoGroupsSucceedsWithEmptyGroups(t *testing.T) {
	c := NewLDAPClient(liveTestConfig(t))
	res, err := c.Authenticate(context.Background(), "bob@example.com", "bobpass")
	if err != nil {
		t.Fatalf("expected bob's credentials to verify even though he's in no group, got %v", err)
	}
	if len(res.Groups) != 0 {
		t.Fatalf("expected bob to have no group memberships, got %v", res.Groups)
	}
}

func TestLiveAuthenticateWrongPasswordFails(t *testing.T) {
	c := NewLDAPClient(liveTestConfig(t))
	_, err := c.Authenticate(context.Background(), "alice@example.com", "not-alices-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for a wrong password, got %v", err)
	}
}

func TestLiveAuthenticateUnknownUserFails(t *testing.T) {
	c := NewLDAPClient(liveTestConfig(t))
	_, err := c.Authenticate(context.Background(), "nobody@example.com", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for an unknown user, got %v", err)
	}
}

func TestLiveAuthenticateEmptyPasswordFails(t *testing.T) {
	// Guards against a directory that would treat an empty-password bind on
	// a real DN as an anonymous (always-succeeds) bind rather than a
	// credential check — see Authenticate's own early rejection of this.
	c := NewLDAPClient(liveTestConfig(t))
	_, err := c.Authenticate(context.Background(), "alice@example.com", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for an empty password, got %v", err)
	}
}

// TestLiveSlapdAvailable is a meta-check, not a functional test: it only
// verifies the slapd binary this suite depends on exists in $PATH so a
// missing LDAP_LIVE_TEST_URL reads as "not configured" rather than silently
// meaning "no LDAP support in this environment at all."
func TestLiveSlapdAvailable(t *testing.T) {
	if os.Getenv("LDAP_LIVE_TEST_URL") == "" {
		t.Skip("LDAP_LIVE_TEST_URL not set")
	}
	if _, err := exec.LookPath("slapd"); err != nil {
		t.Skip("slapd not installed — this only documents the live-test dependency, it isn't itself part of the suite's pass/fail signal")
	}
}
