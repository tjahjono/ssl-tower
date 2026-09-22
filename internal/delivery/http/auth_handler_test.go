package http

import (
	"testing"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

func TestOnboardingRedirectPath(t *testing.T) {
	cases := []struct {
		name string
		user domain.User
		want string
	}{
		{"needs both, password change wins", domain.User{MustChangePassword: true, MFAEnabled: false}, "/account/password"},
		{"needs password change only", domain.User{MustChangePassword: true, MFAEnabled: true}, "/account/password"},
		{"needs MFA enrollment only", domain.User{MustChangePassword: false, MFAEnabled: false}, "/account/mfa/enroll"},
		{"fully onboarded", domain.User{MustChangePassword: false, MFAEnabled: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := onboardingRedirectPath(&c.user); got != c.want {
				t.Errorf("onboardingRedirectPath(%+v) = %q, want %q", c.user, got, c.want)
			}
		})
	}
}

func TestSafeNext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/certificates", "/certificates"},
		{"/certificates/123", "/certificates/123"},
		// Protocol-relative and backslash-normalized bypasses — a CodeQL
		// go/bad-redirect-check finding caught the backslash case, since an
		// earlier version of this check only rejected "//".
		{"//evil.com", "/"},
		{"/\\evil.com", "/"},
		{"\\evil.com", "/"},
		{"http://evil.com", "/"},
		{"https://evil.com", "/"},
		{"/", "/"},
	}
	for _, c := range cases {
		if got := safeNext(c.in); got != c.want {
			t.Errorf("safeNext(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
