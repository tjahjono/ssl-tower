package service

import (
	"context"
	"testing"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/graphmail"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
)

// fakeSettingsRepository is a minimal in-memory domain.SettingsRepository,
// mirroring the fake*Repo shape used throughout this package's tests.
type fakeSettingsRepository struct {
	values    map[string]string
	updatedBy string
	setCalls  int
}

func newFakeSettingsRepository() *fakeSettingsRepository {
	return &fakeSettingsRepository{values: map[string]string{}}
}

func (f *fakeSettingsRepository) Get(_ context.Context, key string) (string, bool, error) {
	v, ok := f.values[key]
	return v, ok, nil
}

func (f *fakeSettingsRepository) GetAll(_ context.Context) (map[string]string, error) {
	out := make(map[string]string, len(f.values))
	for k, v := range f.values {
		out[k] = v
	}
	return out, nil
}

func (f *fakeSettingsRepository) SetMany(_ context.Context, values map[string]string, updatedBy string) error {
	for k, v := range values {
		f.values[k] = v
	}
	f.updatedBy = updatedBy
	f.setCalls++
	return nil
}

var _ domain.SettingsRepository = (*fakeSettingsRepository)(nil)

func testSeed() SeedValues {
	return SeedValues{
		Settings: domain.AppSettings{
			ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1,
			SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPUsername: "user", SMTPPassword: "pass",
			AlertEmailFrom: "alerts@example.com", AlertEmailTo: []string{"team@example.com"},
			TeamsWebhookURL: "https://example.com/webhook",
			TicketSLADays:   3,
		},
		EncryptionKey: "seed-key",
	}
}

func TestBootstrapSeedsEveryKeyOnFreshDatabase(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())

	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	cur := svc.Current()
	if cur.ExpiryWarningDays != 30 || cur.ExpiryCriticalDays != 7 || cur.ExpiryFinalDays != 1 {
		t.Fatalf("expiry thresholds not seeded: %+v", cur)
	}
	if cur.SMTPHost != "smtp.example.com" || cur.SMTPPort != 587 {
		t.Fatalf("SMTP settings not seeded: %+v", cur)
	}
	if cur.TicketSLADays != 3 {
		t.Fatalf("TicketSLADays = %d, want 3", cur.TicketSLADays)
	}
	key, err := svc.EncryptionKeyValue(context.Background())
	if err != nil {
		t.Fatalf("EncryptionKeyValue: %v", err)
	}
	if key != "seed-key" {
		t.Fatalf("EncryptionKeyValue = %q, want seed-key", key)
	}
}

// TestBootstrapNeverOverwritesAlreadySeededKeys is the core guarantee this
// service exists for: once app_settings has a row for a key (an admin
// edited it, or an earlier boot seeded it), later boots must leave it
// alone even if .env's seed value has since changed — the portal is
// authoritative from that point on, not .env.
func TestBootstrapNeverOverwritesAlreadySeededKeys(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	// Simulate an admin editing one setting through the portal after the
	// first boot.
	if err := svc.Update(context.Background(), domain.AppSettings{
		ExpiryWarningDays: 45, ExpiryCriticalDays: 10, ExpiryFinalDays: 2,
		SMTPHost: "smtp.example.com", SMTPPort: 587,
		TicketSLADays: 3,
	}, "admin@example.com"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A later boot with a *different* .env seed must not clobber the
	// admin's edit.
	laterSeed := testSeed()
	laterSeed.Settings.ExpiryWarningDays = 999
	laterSeed.EncryptionKey = "a-different-key"
	if err := svc.Bootstrap(context.Background(), laterSeed); err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}

	if got := svc.Current().ExpiryWarningDays; got != 45 {
		t.Fatalf("ExpiryWarningDays = %d, want 45 (the admin's edit, not the later .env seed's 999)", got)
	}
	key, err := svc.EncryptionKeyValue(context.Background())
	if err != nil {
		t.Fatalf("EncryptionKeyValue: %v", err)
	}
	if key != "seed-key" {
		t.Fatalf("EncryptionKeyValue = %q, want the original seed-key untouched by the second boot's seed", key)
	}
}

// TestBootstrapSeedsOnlyMissingKeysIndividually confirms seeding is checked
// per-key, not table-wide — a brand-new setting key added in a future
// version still gets seeded even when every other key already has a row.
func TestBootstrapSeedsOnlyMissingKeysIndividually(t *testing.T) {
	repo := newFakeSettingsRepository()
	repo.values[domain.SettingTicketSLADays] = "9" // pretend an admin already set this one

	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	cur := svc.Current()
	if cur.TicketSLADays != 9 {
		t.Fatalf("TicketSLADays = %d, want the pre-existing 9 left untouched", cur.TicketSLADays)
	}
	if cur.ExpiryWarningDays != 30 {
		t.Fatalf("ExpiryWarningDays = %d, want 30 seeded from testSeed()", cur.ExpiryWarningDays)
	}
}

func TestUpdateRejectsCriticalDaysAboveWarningDays(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	err := svc.Update(context.Background(), domain.AppSettings{
		ExpiryWarningDays: 7, ExpiryCriticalDays: 30, ExpiryFinalDays: 1,
		TicketSLADays: 3,
	}, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError for critical > warning, got %v", err)
	}
}

func TestUpdateRejectsFinalDaysAboveCriticalDays(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	err := svc.Update(context.Background(), domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 20,
		TicketSLADays: 3,
	}, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError for final > critical, got %v", err)
	}
}

// validLDAPPatch is a minimally valid AppSettings patch for LDAP-focused
// Update tests — non-LDAP fields are set to values that pass the other
// cross-field checks so a test only has to vary LDAP fields.
func validLDAPPatch() domain.AppSettings {
	return domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3,
		LDAPURL:    "ldap://ldap.example.com:389",
		LDAPBindDN: "cn=svc,dc=example,dc=com", LDAPBindPassword: "svcpass",
		LDAPBaseDN:        "dc=example,dc=com",
		LDAPUserFilter:    "(mail=%s)",
		LDAPGroupFilter:   "(&(objectClass=groupOfNames)(member=%s))",
		LDAPRoleMapEditor: []string{"cn=editors,ou=groups,dc=example,dc=com"},
	}
}

func TestUpdateAcceptsValidLDAPConfig(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if err := svc.Update(context.Background(), validLDAPPatch(), "admin@example.com"); err != nil {
		t.Fatalf("Update: unexpected error with a fully valid LDAP config: %v", err)
	}
	cur := svc.Current()
	if cur.LDAPURL != "ldap://ldap.example.com:389" {
		t.Fatalf("LDAPURL = %q, want the saved value", cur.LDAPURL)
	}
	if len(cur.LDAPRoleMapEditor) != 1 || cur.LDAPRoleMapEditor[0] != "cn=editors,ou=groups,dc=example,dc=com" {
		t.Fatalf("LDAPRoleMapEditor = %v, want a single parsed DN", cur.LDAPRoleMapEditor)
	}
}

func TestUpdateRejectsLDAPMissingRequiredField(t *testing.T) {
	fields := map[string]func(*domain.AppSettings){
		"LDAPBindDN":       func(p *domain.AppSettings) { p.LDAPBindDN = "" },
		"LDAPBindPassword": func(p *domain.AppSettings) { p.LDAPBindPassword = "" },
		"LDAPBaseDN":       func(p *domain.AppSettings) { p.LDAPBaseDN = "" },
		"LDAPUserFilter":   func(p *domain.AppSettings) { p.LDAPUserFilter = "" },
		"LDAPGroupFilter":  func(p *domain.AppSettings) { p.LDAPGroupFilter = "" },
	}
	for name, clear := range fields {
		t.Run(name, func(t *testing.T) {
			repo := newFakeSettingsRepository()
			svc := NewSettingsService(repo, discardLogger())
			if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
				t.Fatalf("Bootstrap: %v", err)
			}
			patch := validLDAPPatch()
			clear(&patch)

			err := svc.Update(context.Background(), patch, "admin@example.com")
			if _, ok := domain.AsValidation(err); !ok {
				t.Fatalf("Update: expected a ValidationError with %s cleared while LDAPURL is set, got %v", name, err)
			}
		})
	}
}

func TestUpdateRejectsLDAPFilterWithoutPlaceholder(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	patch := validLDAPPatch()
	patch.LDAPUserFilter = "(mail=nobody@example.com)"

	err := svc.Update(context.Background(), patch, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError for a user filter with no placeholder, got %v", err)
	}
}

func TestUpdateRejectsLDAPWithNoRoleMappingConfigured(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	patch := validLDAPPatch()
	patch.LDAPRoleMapEditor = nil

	err := svc.Update(context.Background(), patch, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError when no role mapping would ever let a login succeed, got %v", err)
	}
}

func TestUpdateWithoutLDAPURLIgnoresOtherLDAPFields(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// LDAPURL left empty — the "empty = off" toggle — even though nothing
	// else LDAP-related is set either.
	patch := domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3}
	if err := svc.Update(context.Background(), patch, "admin@example.com"); err != nil {
		t.Fatalf("Update: expected no error with LDAPURL empty, got %v", err)
	}
}

// TestSettingsReloadSplitsLDAPRoleMapsOnSemicolonNotComma guards against the
// exact gotcha CLAUDE.md's v1.4 LDAP section documents: a DN's own RDN
// components are comma-separated, so a comma-based split would shred one DN
// into bogus fragments.
func TestSettingsReloadSplitsLDAPRoleMapsOnSemicolonNotComma(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	patch := validLDAPPatch()
	patch.LDAPRoleMapEditor = []string{
		"cn=sslgen-editors,ou=groups,dc=example,dc=com",
		"cn=platform-team,ou=groups,dc=example,dc=com",
	}
	if err := svc.Update(context.Background(), patch, "admin@example.com"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	cur := svc.Current()
	want := []string{"cn=sslgen-editors,ou=groups,dc=example,dc=com", "cn=platform-team,ou=groups,dc=example,dc=com"}
	if len(cur.LDAPRoleMapEditor) != len(want) {
		t.Fatalf("LDAPRoleMapEditor = %v, want %v", cur.LDAPRoleMapEditor, want)
	}
	for i, dn := range want {
		if cur.LDAPRoleMapEditor[i] != dn {
			t.Fatalf("LDAPRoleMapEditor[%d] = %q, want %q — a comma-based split would have shredded these DNs", i, cur.LDAPRoleMapEditor[i], dn)
		}
	}
}

// validADCSPatch mirrors validLDAPPatch's role for ADCS's own cross-field
// check (v1.16).
func validADCSPatch() domain.AppSettings {
	return domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3,
		ADCSEndpoint: "https://adcs.example.com/ADPolicyProvider_CEP_UsernamePassword/service.svc/CES",
		ADCSUsername: "svc-adcs", ADCSPassword: "svcpass", ADCSTemplate: "WebServer",
	}
}

func TestUpdateAcceptsValidADCSConfig(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if err := svc.Update(context.Background(), validADCSPatch(), "admin@example.com"); err != nil {
		t.Fatalf("Update: unexpected error with a fully valid ADCS config: %v", err)
	}
	cur := svc.Current()
	if cur.ADCSTemplate != "WebServer" {
		t.Fatalf("ADCSTemplate = %q, want the saved value", cur.ADCSTemplate)
	}
}

func TestUpdateRejectsADCSMissingRequiredField(t *testing.T) {
	fields := map[string]func(*domain.AppSettings){
		"ADCSUsername": func(p *domain.AppSettings) { p.ADCSUsername = "" },
		"ADCSPassword": func(p *domain.AppSettings) { p.ADCSPassword = "" },
		"ADCSTemplate": func(p *domain.AppSettings) { p.ADCSTemplate = "" },
	}
	for name, clear := range fields {
		t.Run(name, func(t *testing.T) {
			repo := newFakeSettingsRepository()
			svc := NewSettingsService(repo, discardLogger())
			if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
				t.Fatalf("Bootstrap: %v", err)
			}
			patch := validADCSPatch()
			clear(&patch)

			err := svc.Update(context.Background(), patch, "admin@example.com")
			if _, ok := domain.AsValidation(err); !ok {
				t.Fatalf("Update: expected a ValidationError with %s cleared while ADCSEndpoint is set, got %v", name, err)
			}
		})
	}
}

func TestUpdateWithoutADCSEndpointIgnoresOtherADCSFields(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// ADCSEndpoint left empty — the "empty = off" toggle — even though
	// nothing else ADCS-related is set either.
	patch := domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3}
	if err := svc.Update(context.Background(), patch, "admin@example.com"); err != nil {
		t.Fatalf("Update: expected no error with ADCSEndpoint empty, got %v", err)
	}
}

func TestUpdateTakesEffectImmediatelyOnCurrent(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	patch := domain.AppSettings{
		ExpiryWarningDays: 20, ExpiryCriticalDays: 5, ExpiryFinalDays: 1,
		SMTPHost: "smtp.new.example.com", SMTPPort: 25,
		TicketSLADays: 5,
	}
	if err := svc.Update(context.Background(), patch, "admin@example.com"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	cur := svc.Current()
	if cur.ExpiryWarningDays != 20 || cur.SMTPHost != "smtp.new.example.com" || cur.TicketSLADays != 5 {
		t.Fatalf("Current() didn't reflect Update's patch: %+v", cur)
	}
	if repo.updatedBy != "admin@example.com" {
		t.Fatalf("repo updatedBy = %q, want admin@example.com", repo.updatedBy)
	}
}

// TestEncryptionKeyValueNeverAppearsInAppSettings confirms the encryption
// key stays out of the generic get-all/update surface entirely — it's read
// through its own dedicated method, never via Current().
func TestEncryptionKeyValueNeverAppearsInAppSettings(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// domain.AppSettings has no encryption-key field for a stray seed-key
	// value to leak into — this assertion documents that invariant by
	// confirming Update's own field set never includes it, i.e. an Update
	// call can't accidentally clobber the encryption key.
	if err := svc.Update(context.Background(), domain.AppSettings{TicketSLADays: 3}, "admin@example.com"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	key, err := svc.EncryptionKeyValue(context.Background())
	if err != nil {
		t.Fatalf("EncryptionKeyValue: %v", err)
	}
	if key != "seed-key" {
		t.Fatalf("EncryptionKeyValue = %q, want seed-key unaffected by an unrelated Update", key)
	}
}

func validGraphPatch() domain.AppSettings {
	return domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3,
		EmailTransport: domain.EmailTransportGraph,
		GraphTenantID:  "tenant-id", GraphClientID: "client-id",
		GraphClientSecret: "client-secret", GraphSenderAddress: "alerts@example.com",
	}
}

func TestUpdateAcceptsValidGraphConfig(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if err := svc.Update(context.Background(), validGraphPatch(), "admin@example.com"); err != nil {
		t.Fatalf("Update: unexpected error with a fully valid Graph config: %v", err)
	}
	cur := svc.Current()
	if cur.EmailTransport != domain.EmailTransportGraph || cur.GraphSenderAddress != "alerts@example.com" {
		t.Fatalf("Graph settings not saved: %+v", cur)
	}
}

func TestUpdateRejectsGraphMissingRequiredField(t *testing.T) {
	fields := map[string]func(*domain.AppSettings){
		"GraphClientID":      func(p *domain.AppSettings) { p.GraphClientID = "" },
		"GraphClientSecret":  func(p *domain.AppSettings) { p.GraphClientSecret = "" },
		"GraphSenderAddress": func(p *domain.AppSettings) { p.GraphSenderAddress = "" },
	}
	for name, clear := range fields {
		t.Run(name, func(t *testing.T) {
			repo := newFakeSettingsRepository()
			svc := NewSettingsService(repo, discardLogger())
			if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
				t.Fatalf("Bootstrap: %v", err)
			}
			patch := validGraphPatch()
			clear(&patch)

			err := svc.Update(context.Background(), patch, "admin@example.com")
			if _, ok := domain.AsValidation(err); !ok {
				t.Fatalf("Update: expected a ValidationError with %s cleared while GraphTenantID is set, got %v", name, err)
			}
		})
	}
}

func TestUpdateWithoutGraphTenantIDIgnoresOtherGraphFields(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// GraphTenantID left empty — the "empty = off" toggle — even though
	// EmailTransport is left at its zero value (not "graph") too, so
	// nothing about the Graph section is configured at all.
	patch := domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3}
	if err := svc.Update(context.Background(), patch, "admin@example.com"); err != nil {
		t.Fatalf("Update: expected no error with GraphTenantID empty, got %v", err)
	}
}

// TestUpdateRejectsGraphTransportWithoutTenantID confirms EmailTransport
// can't be switched to "graph" while the Graph section is left unfilled —
// distinct from the "empty = off" toggle case above, since here
// EmailTransport itself is the thing demanding the Graph fields exist,
// independently of whether GraphTenantID happens to be set.
func TestUpdateRejectsGraphTransportWithoutTenantID(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	patch := domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3,
		EmailTransport: domain.EmailTransportGraph,
	}
	err := svc.Update(context.Background(), patch, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError when EmailTransport=graph but GraphTenantID is empty, got %v", err)
	}
}

// TestUpdateRejectsUnknownEmailTransport confirms EmailTransport is
// restricted to the two known values, rather than silently accepting a
// typo and falling back to SMTP with no indication anything was wrong.
func TestUpdateRejectsUnknownEmailTransport(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	patch := domain.AppSettings{
		ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1, TicketSLADays: 3,
		EmailTransport: "carrier-pigeon",
	}
	err := svc.Update(context.Background(), patch, "admin@example.com")
	if _, ok := domain.AsValidation(err); !ok {
		t.Fatalf("Update: expected a ValidationError for an unrecognized email_transport value, got %v", err)
	}
}

// TestMailerSelectsTransportFromCurrentSettings confirms Mailer() switches
// between the SMTP-backed EmailNotifier and a graphmail.Notifier purely
// based on the live EmailTransport setting — the whole point of routing
// every caller through Mailer() instead of EmailNotifier() directly.
func TestMailerSelectsTransportFromCurrentSettings(t *testing.T) {
	repo := newFakeSettingsRepository()
	svc := NewSettingsService(repo, discardLogger())
	if err := svc.Bootstrap(context.Background(), testSeed()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// testSeed() carries no EmailTransport, and Bootstrap defaults an empty
	// seed value to "smtp" — so with no Update at all yet, Mailer() should
	// already be the SMTP notifier.
	if _, ok := svc.Mailer().(*notify.EmailNotifier); !ok {
		t.Fatalf("Mailer() = %T, want *notify.EmailNotifier when EmailTransport defaults to smtp", svc.Mailer())
	}

	if err := svc.Update(context.Background(), validGraphPatch(), "admin@example.com"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, ok := svc.Mailer().(*graphmail.Notifier); !ok {
		t.Fatalf("Mailer() = %T, want *graphmail.Notifier once EmailTransport is graph", svc.Mailer())
	}
}
