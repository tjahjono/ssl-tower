package http

import "testing"

// TestRendererBoots parses every template at once, the same way NewServer
// does at process startup — a fast, dependency-free way to catch a typo'd
// {{template}} reference or an unbalanced {{define}}/{{end}} before it ever
// reaches a running server. Regressions here are exactly the kind of bug a
// new ticket template (or any new page) can introduce silently.
func TestRendererBoots(t *testing.T) {
	if _, err := NewRenderer(); err != nil {
		t.Fatalf("template set failed to parse: %v", err)
	}
}
