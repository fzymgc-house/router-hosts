// Package dockergate decides whether a missing or unreachable Docker
// precondition should skip a test or fail it, without depending on Docker,
// on a build tag, or on the "testing" package. Keeping the decision here —
// tag-free and pure — makes it unit-testable in the ordinary Test job on
// every PR, rather than covered only by a docker_e2e-tagged tier that could
// itself be skipped.
package dockergate

// EnvVar is the environment variable that promotes a missing Docker
// precondition from a skip to a hard failure. It is the single source of
// truth for the variable's spelling: CI workflow YAML and Go test code must
// both reference this constant rather than the string literal, so the two
// cannot drift to different names.
const EnvVar = "RH_E2E_REQUIRE_DOCKER"

// Action is the outcome of a Docker precondition check.
type Action int

const (
	// Proceed means the precondition is satisfied; the test should run.
	// It is the zero value, so a forgotten assignment fails toward running
	// the test rather than toward silently skipping it.
	Proceed Action = iota
	// Skip means the precondition failed but was not required; the test
	// should call t.Skip.
	Skip
	// Fatal means the precondition failed and was required; the test
	// should call t.Fatalf.
	Fatal
)

// Decide returns the Action a Docker precondition check should take, given
// the raw value of EnvVar and the error (if any) from probing Docker.
//
// Decide returns Proceed whenever probeErr is nil, regardless of envValue.
// Otherwise it returns Fatal when envValue is non-empty and Skip when
// envValue is empty.
//
// The check is presence-based, not truthiness-based: any non-empty value —
// including "0" or whitespace — means the requirement is set. Decide never
// parses envValue as a bool and never trims it, so a CI job that sets
// EnvVar to "1" cannot be silently defeated by a future edit that "helpfully"
// adds boolean parsing.
func Decide(envValue string, probeErr error) Action {
	if probeErr == nil {
		return Proceed
	}
	if envValue != "" {
		return Fatal
	}
	return Skip
}
