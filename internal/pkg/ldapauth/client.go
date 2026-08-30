// Package ldapauth authenticates users against an external LDAP directory
// using the standard "search-then-bind" pattern: bind as a service account,
// search for the submitted email under the configured base DN, then attempt
// a second bind as that entry's DN with the submitted password to actually
// verify it. A successful authentication also resolves which groups the
// entry belongs to (searched with the service account's own credentials,
// not the user's), so AuthService can map LDAP group membership onto one of
// this app's roles.
//
// Unlike internal/pkg/digicert — a proprietary REST API this app has no
// live credentials to test against — LDAP is a standardized protocol
// (RFC 4511) with a mature open-source server (OpenLDAP/slapd) and a mature
// Go client library (github.com/go-ldap/ldap/v3). That means LDAPClient
// below can be, and is, exercised directly against a real slapd instance in
// this package's tests rather than only through a fake — see
// client_live_test.go. The Client interface still exists and AuthService
// still depends only on it, for the same isolation reason digicert.Client
// does: AuthService's own tests don't need a running directory server, and
// swapping the implementation later (a different library, a mock directory)
// touches only this package.
package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// dialTimeout bounds how long a single connection attempt (service bind or
// user credential bind) may take — the go-ldap v3 API this package targets
// dials by URL rather than by context, so a context deadline on the calling
// request does not by itself abort a hung TCP handshake; this is the
// backstop.
const dialTimeout = 10 * time.Second

// ErrInvalidCredentials covers every reason Authenticate can fail because of
// what the caller supplied — no directory entry matched the email, the
// entry had no bindable DN, or the password didn't verify. Deliberately one
// error for all three cases: distinguishing "no such LDAP user" from "wrong
// password" in the response would just hand an attacker a username oracle,
// exactly why AuthService already collapses the equivalent local-auth cases
// (domain.ErrUnauthorized) the same way.
var ErrInvalidCredentials = errors.New("ldapauth: invalid credentials")

// AuthResult is what a successful Authenticate call returns.
type AuthResult struct {
	// DN is the authenticated entry's distinguished name.
	DN string
	// Groups lists the DN of every group entry the user belongs to, as
	// resolved by the configured group filter. May be empty — that's a
	// normal, if very likely fail-closed-denied, outcome, not an error.
	Groups []string
}

// Client is the seam between AuthService and the network.
type Client interface {
	// Authenticate verifies email/password against the directory and
	// resolves group membership on success. Returns ErrInvalidCredentials
	// for any authentication failure, or a wrapped error for anything else
	// (the directory unreachable, a malformed filter, and so on) — callers
	// should treat only ErrInvalidCredentials as "the credentials were
	// wrong" and everything else as an operational failure worth logging
	// distinctly.
	Authenticate(ctx context.Context, email, password string) (*AuthResult, error)
}

// Config is everything LDAPClient needs to reach and query the directory.
// Every field is required — there is no partially-configured state; see
// config.Load's LDAP_* handling for the "empty LDAP_URL disables the whole
// feature" toggle this backs.
type Config struct {
	// URL is the directory's LDAP URL, e.g. "ldap://ldap.example.com:389"
	// or "ldaps://ldap.example.com:636".
	URL string
	// BindDN and BindPassword are the service account used for the search
	// half of search-then-bind, and for the group-membership lookup — never
	// the end user's own credentials.
	BindDN       string
	BindPassword string
	// BaseDN is the search base for both the user and group searches.
	BaseDN string
	// UserFilter finds a user's entry by email — exactly one "%s"
	// placeholder, replaced with the filter-escaped email, e.g.
	// "(mail=%s)" or "(&(objectClass=inetOrgPerson)(uid=%s))".
	UserFilter string
	// GroupFilter finds every group a user's entry belongs to — exactly one
	// "%s" placeholder, replaced with the filter-escaped user DN, e.g.
	// "(&(objectClass=groupOfNames)(member=%s))".
	GroupFilter string
	// InsecureSkipVerify disables TLS certificate verification for ldaps://
	// connections — off by default; only meant for pointing at a self-signed
	// test directory (see client_live_test.go), never production.
	InsecureSkipVerify bool
}

// LDAPClient is the real Client implementation, backed by
// github.com/go-ldap/ldap/v3.
type LDAPClient struct {
	cfg Config
}

// NewLDAPClient builds a client from cfg. It does not connect — a bad URL or
// unreachable directory only surfaces on the first Authenticate call, same
// as digicert.NewHTTPClient.
func NewLDAPClient(cfg Config) *LDAPClient {
	return &LDAPClient{cfg: cfg}
}

var _ Client = (*LDAPClient)(nil)

// Authenticate implements Client.
func (c *LDAPClient) Authenticate(ctx context.Context, email, password string) (*AuthResult, error) {
	// An empty password would make some directories treat the final bind as
	// an anonymous (always-succeeds) bind rather than a credential check —
	// reject it outright rather than relying on every possible directory
	// server to refuse it itself.
	if strings.TrimSpace(password) == "" {
		return nil, ErrInvalidCredentials
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldapauth: connect: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldapauth: service account bind: %w", err)
	}

	userDN, err := c.searchOne(conn, c.cfg.UserFilter, email)
	if err != nil {
		if errors.Is(err, errNoResult) || errors.Is(err, errAmbiguous) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("ldapauth: search user: %w", err)
	}

	groups, err := c.searchGroups(conn, userDN)
	if err != nil {
		return nil, fmt.Errorf("ldapauth: search groups: %w", err)
	}

	// A fresh connection for the credential check, rather than re-binding
	// conn above: once a connection is bound as the end user, it can no
	// longer be trusted to run further service-account-privileged searches,
	// and the group lookup above already needed to happen first (some
	// directories restrict what an ordinary user can read about groups).
	userConn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldapauth: connect: %w", err)
	}
	defer userConn.Close()

	if err := userConn.Bind(userDN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &AuthResult{DN: userDN, Groups: groups}, nil
}

func (c *LDAPClient) dial(ctx context.Context) (*ldap.Conn, error) {
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout})}
	if strings.HasPrefix(c.cfg.URL, "ldaps://") && c.cfg.InsecureSkipVerify {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only opt-in, see Config.InsecureSkipVerify
	}
	conn, err := ldap.DialURL(c.cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}
	return conn, nil
}

var (
	errNoResult  = errors.New("no matching entry")
	errAmbiguous = errors.New("filter matched more than one entry")
)

// searchOne runs filterTemplate with %s replaced by the filter-escaped
// value and returns the single matching entry's DN. More than one match is
// treated as an error, not "pick the first" — an ambiguous user filter is a
// misconfiguration, not something to guess through.
func (c *LDAPClient) searchOne(conn *ldap.Conn, filterTemplate, value string) (string, error) {
	filter := fmt.Sprintf(filterTemplate, ldap.EscapeFilter(value))
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, filter, []string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	switch len(res.Entries) {
	case 0:
		return "", errNoResult
	case 1:
		return res.Entries[0].DN, nil
	default:
		return "", errAmbiguous
	}
}

// searchGroups runs the configured group filter with %s replaced by the
// filter-escaped user DN and returns every matching group's DN.
func (c *LDAPClient) searchGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	filter := fmt.Sprintf(c.cfg.GroupFilter, ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, e.DN)
	}
	return groups, nil
}
