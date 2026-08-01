// Package sanitize is the shared newline-collapsing helper for any text that
// is emitted into a line-oriented config file (hosts, dnsmasq, unbound). It
// exists because of the GH #349 review finding router-hosts-00b.2: a Comment
// or Tag containing a newline would otherwise break out of a "# ..." comment
// line and inject active resolver directives into the generated output.
//
// This is the single implementation both the server-side output generators
// (internal/server) and the client-side template FuncMap (D-17, contract v1)
// reach, so the two call paths cannot silently diverge in behavior.
package sanitize

import "strings"

// lineBreakReplacer collapses CR and LF to spaces so user-supplied comment
// or tag text stays on a single line in generated config files. It operates
// on bytes: only 0x0A and 0x0D are replaced, and every other byte — including
// multi-byte UTF-8 sequences and other Unicode line-break characters such as
// U+2028 — passes through untouched. This is deliberately not Unicode-aware
// line-break normalisation; it targets exactly the two bytes that terminate
// a line in the resolver config formats this package's callers write.
var lineBreakReplacer = strings.NewReplacer("\n", " ", "\r", " ")

// CommentField collapses every LF (0x0A) and CR (0x0D) byte in s to a space,
// leaving all other bytes untouched. Without it, a comment or tag containing
// a newline breaks out of a "# ..." comment line and injects active
// directives into the generated hosts/dnsmasq/unbound output. See GH #349
// review finding router-hosts-00b.2.
func CommentField(s string) string {
	return lineBreakReplacer.Replace(s)
}
