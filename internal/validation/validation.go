// Package validation provides IP address, hostname, and alias validation
// for DNS host entries. Rules follow RFC 1035 for hostnames.
package validation

import (
	"net"
	"regexp"
	"strings"

	"github.com/samber/oops"
)

// MaxAliasesPerEntry is the maximum number of aliases allowed per host entry.
// This prevents resource exhaustion.
const MaxAliasesPerEntry = 50

// labelRegex validates a single DNS label per RFC 1035:
// alphanumeric start/end, hyphens allowed in the middle, 1-63 characters.
var labelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateIPAddress validates an IP address string (IPv4 or IPv6).
// Returns an oops error with code "validation_failed" if invalid.
func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return oops.
			Code("validation_failed").
			Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ValidateHostname validates a DNS hostname per RFC 1035.
//
// Rules:
//   - Total length: 1-253 characters
//   - Labels separated by dots, each 1-63 characters
//   - Labels match: ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$
//   - Cannot start or end with hyphen or dot
//   - No consecutive dots
//   - Empty hostname rejected
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return oops.
			Code("validation_failed").
			Errorf("hostname cannot be empty")
	}

	if len(hostname) > 253 {
		return oops.
			Code("validation_failed").
			Errorf("hostname exceeds maximum length of 253 characters")
	}

	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return oops.
			Code("validation_failed").
			Errorf("hostname cannot start or end with dot")
	}

	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return oops.
			Code("validation_failed").
			Errorf("hostname cannot start or end with hyphen")
	}

	for _, label := range strings.Split(hostname, ".") {
		if label == "" {
			return oops.
				Code("validation_failed").
				Errorf("hostname cannot contain consecutive dots")
		}
		if !labelRegex.MatchString(label) {
			return oops.
				Code("validation_failed").
				Errorf("invalid label '%s' in hostname", label)
		}
	}

	return nil
}

// ValidateAliases validates a list of aliases for a host entry.
// It collects ALL validation errors rather than returning on the first one.
//
// Rules:
//   - Maximum MaxAliasesPerEntry aliases (returns immediately if exceeded)
//   - Each alias must be a valid hostname
//   - Cannot match canonical hostname (case-insensitive)
//   - No duplicate aliases (case-insensitive)
//   - Cannot be an IP address (checked before hostname validation for better
//     error messages on IPv6 addresses like "::1")
func ValidateAliases(aliases []string, canonicalHostname string) []error {
	if len(aliases) > MaxAliasesPerEntry {
		return []error{
			oops.
				Code("too_many_aliases").
				Errorf("too many aliases: %d exceeds maximum of %d",
					len(aliases), MaxAliasesPerEntry),
		}
	}

	var errs []error
	seen := make(map[string]struct{}, len(aliases))

	for _, alias := range aliases {
		// Check for IP address FIRST (before hostname validation).
		// This gives a more specific error for IPv6 addresses like "::1"
		// which would otherwise fail hostname validation due to colons.
		if net.ParseIP(alias) != nil {
			errs = append(errs, oops.
				Code("alias_is_ip_address").
				Errorf("alias '%s' cannot be an IP address", alias))
			continue
		}

		// Validate as hostname (after IP check).
		if err := ValidateHostname(alias); err != nil {
			errs = append(errs, oops.Code("validation_failed").Wrapf(err, "invalid alias '%s'", alias))
			continue
		}

		// Cannot match canonical hostname (case-insensitive).
		if strings.EqualFold(alias, canonicalHostname) {
			errs = append(errs, oops.
				Code("alias_matches_hostname").
				Errorf("alias '%s' matches canonical hostname", alias))
		}

		// No duplicates (case-insensitive).
		lower := strings.ToLower(alias)
		if _, exists := seen[lower]; exists {
			errs = append(errs, oops.
				Code("duplicate_alias").
				Errorf("duplicate alias '%s' in entry", alias))
		}
		seen[lower] = struct{}{}
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}
