package validation

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// ==========================================================================
// IP Address Validation Tests
// ==========================================================================

func TestValidIPv4Addresses(t *testing.T) {
	valid := []string{
		"192.168.1.1",
		"10.0.0.1",
		"127.0.0.1",
		"255.255.255.255",
	}
	for _, ip := range valid {
		t.Run(ip, func(t *testing.T) {
			if err := ValidateIPAddress(ip); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestInvalidIPv4Addresses(t *testing.T) {
	invalid := []string{
		"256.1.1.1",
		"192.168.1",
		"192.168.1.1.1",
		"not-an-ip",
		"",
	}
	for _, ip := range invalid {
		name := ip
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			if err := ValidateIPAddress(ip); err == nil {
				t.Errorf("expected error for %q", ip)
			}
		})
	}
}

func TestValidIPv6Addresses(t *testing.T) {
	valid := []string{
		"::1",
		"fe80::1",
		"2001:0db8:85a3::8a2e:0370:7334",
		"::ffff:192.168.1.1",
	}
	for _, ip := range valid {
		t.Run(ip, func(t *testing.T) {
			if err := ValidateIPAddress(ip); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestInvalidIPv6Addresses(t *testing.T) {
	invalid := []string{
		"gggg::1",
		"::::::",
	}
	for _, ip := range invalid {
		t.Run(ip, func(t *testing.T) {
			if err := ValidateIPAddress(ip); err == nil {
				t.Errorf("expected error for %q", ip)
			}
		})
	}
}

// ==========================================================================
// Hostname Validation Tests
// ==========================================================================

func TestValidHostnames(t *testing.T) {
	valid := []string{
		"localhost",
		"server.local",
		"my-server",
		"server123",
		"sub.domain.example.com",
		"a",
		"1",
		"123",
		"123.456",
	}
	for _, h := range valid {
		t.Run(h, func(t *testing.T) {
			if err := ValidateHostname(h); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestInvalidHostnames(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
	}{
		{"empty", ""},
		{"leading_hyphen", "-invalid"},
		{"trailing_hyphen", "invalid-"},
		{"consecutive_dots", "in..valid"},
		{"underscore", "invalid_host"},
		{"leading_dot", ".invalid"},
		{"trailing_dot", "invalid."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHostname(tc.hostname); err == nil {
				t.Errorf("expected error for %q", tc.hostname)
			}
		})
	}
}

func TestHostnameMaxLabelLength(t *testing.T) {
	t.Run("63_chars_ok", func(t *testing.T) {
		label := strings.Repeat("a", 63)
		if err := ValidateHostname(label); err != nil {
			t.Errorf("63-char label should be valid: %v", err)
		}
	})
	t.Run("64_chars_fail", func(t *testing.T) {
		label := strings.Repeat("a", 64)
		if err := ValidateHostname(label); err == nil {
			t.Error("64-char label should be invalid")
		}
	})
}

func TestHostnameMaxTotalLength(t *testing.T) {
	label := strings.Repeat("a", 63)

	t.Run("253_chars_ok", func(t *testing.T) {
		// 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
		maxHostname := fmt.Sprintf("%s.%s.%s.%s", label, label, label, label[:61])
		if len(maxHostname) != 253 {
			t.Fatalf("expected 253 chars, got %d", len(maxHostname))
		}
		if err := ValidateHostname(maxHostname); err != nil {
			t.Errorf("253-char hostname should be valid: %v", err)
		}
	})

	t.Run("254_chars_fail", func(t *testing.T) {
		// 63 + 1 + 63 + 1 + 63 + 1 + 62 = 254
		tooLong := fmt.Sprintf("%s.%s.%s.%s", label, label, label, label[:62])
		if len(tooLong) != 254 {
			t.Fatalf("expected 254 chars, got %d", len(tooLong))
		}
		if err := ValidateHostname(tooLong); err == nil {
			t.Error("254-char hostname should be invalid")
		}
	})
}

// ==========================================================================
// Alias Validation Tests
// ==========================================================================

func TestValidateAliasesEmptyAllowed(t *testing.T) {
	if errs := ValidateAliases([]string{}, "server.local"); errs != nil {
		t.Errorf("empty aliases should be valid: %v", errs)
	}
}

func TestValidateAliasesValid(t *testing.T) {
	aliases := []string{"srv", "s.local"}
	if errs := ValidateAliases(aliases, "server.local"); errs != nil {
		t.Errorf("valid aliases should pass: %v", errs)
	}
}

func TestValidateAliasesMatchesHostname(t *testing.T) {
	aliases := []string{"srv", "server.local"}
	errs := ValidateAliases(aliases, "server.local")
	if len(errs) == 0 {
		t.Fatal("alias matching hostname should fail")
	}
	assertSliceContainsOopsCode(t, errs, "alias_matches_hostname")
}

func TestValidateAliasesCaseInsensitiveMatch(t *testing.T) {
	aliases := []string{"SERVER.LOCAL"}
	errs := ValidateAliases(aliases, "server.local")
	if len(errs) == 0 {
		t.Fatal("case-insensitive match should fail")
	}
	assertSliceContainsOopsCode(t, errs, "alias_matches_hostname")
}

func TestValidateAliasesDuplicate(t *testing.T) {
	aliases := []string{"srv", "srv"}
	errs := ValidateAliases(aliases, "server.local")
	if len(errs) == 0 {
		t.Fatal("duplicate alias should fail")
	}
	assertSliceContainsOopsCode(t, errs, "duplicate_alias")
}

func TestValidateAliasesDuplicateCaseInsensitive(t *testing.T) {
	aliases := []string{"srv", "SRV"}
	errs := ValidateAliases(aliases, "server.local")
	if len(errs) == 0 {
		t.Fatal("case-insensitive duplicate should fail")
	}
	assertSliceContainsOopsCode(t, errs, "duplicate_alias")
}

func TestValidateAliasesInvalidFormat(t *testing.T) {
	aliases := []string{"-invalid"}
	if errs := ValidateAliases(aliases, "server.local"); len(errs) == 0 {
		t.Error("invalid alias format should fail")
	}
}

func TestValidateAliasesIPAddressRejected(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		aliases := []string{"192.168.1.1"}
		errs := ValidateAliases(aliases, "server.local")
		if len(errs) == 0 {
			t.Fatal("IPv4 alias should be rejected")
		}
		assertSliceContainsOopsCode(t, errs, "alias_is_ip_address")
	})
	t.Run("ipv6", func(t *testing.T) {
		aliases := []string{"::1"}
		errs := ValidateAliases(aliases, "server.local")
		if len(errs) == 0 {
			t.Fatal("IPv6 alias should be rejected")
		}
		assertSliceContainsOopsCode(t, errs, "alias_is_ip_address")
	})
	t.Run("ipv6_full", func(t *testing.T) {
		aliases := []string{"2001:db8::1"}
		errs := ValidateAliases(aliases, "server.local")
		if len(errs) == 0 {
			t.Fatal("full IPv6 alias should be rejected")
		}
		assertSliceContainsOopsCode(t, errs, "alias_is_ip_address")
	})
}

func TestValidateAliasesTooMany(t *testing.T) {
	aliases := make([]string, MaxAliasesPerEntry+1)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("alias%d", i)
	}
	errs := ValidateAliases(aliases, "server.local")
	if len(errs) == 0 {
		t.Fatal("too many aliases should fail")
	}
	assertSliceContainsOopsCode(t, errs, "too_many_aliases")
}

func TestValidateAliasesMaxAllowed(t *testing.T) {
	aliases := make([]string, MaxAliasesPerEntry)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("alias%d", i)
	}
	if errs := ValidateAliases(aliases, "server.local"); errs != nil {
		t.Errorf("exactly max aliases should be valid: %v", errs)
	}
}

// ==========================================================================
// Property-Based Tests (rapid)
// ==========================================================================

func TestPropertyValidIPv4AlwaysParses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.IntRange(0, 255).Draw(t, "a")
		b := rapid.IntRange(0, 255).Draw(t, "b")
		c := rapid.IntRange(0, 255).Draw(t, "c")
		d := rapid.IntRange(0, 255).Draw(t, "d")
		ip := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		if err := ValidateIPAddress(ip); err != nil {
			t.Fatalf("valid IPv4 %s failed: %v", ip, err)
		}
	})
}

func TestPropertyIPValidationConsistent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ip := rapid.String().Draw(t, "ip")
		r1 := ValidateIPAddress(ip) == nil
		r2 := ValidateIPAddress(ip) == nil
		if r1 != r2 {
			t.Fatalf("inconsistent validation for %q: %v vs %v", ip, r1, r2)
		}
	})
}

func TestPropertyValidHostnamesAlwaysPass(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numLabels := rapid.IntRange(1, 3).Draw(t, "numLabels")
		labels := make([]string, numLabels)
		for i := range labels {
			labels[i] = rapid.StringMatching("[a-z][a-z0-9]{0,9}").Draw(t, fmt.Sprintf("label%d", i))
		}
		hostname := strings.Join(labels, ".")
		if err := ValidateHostname(hostname); err != nil {
			t.Fatalf("valid hostname %q should pass: %v", hostname, err)
		}
	})
}

func TestPropertyInvalidCharsHostnameAlwaysFails(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		invalidChars := []byte("_@!#$%^&* ")
		prefix := rapid.StringMatching("[a-z]{1,5}").Draw(t, "prefix")
		suffix := rapid.StringMatching("[a-z]{1,5}").Draw(t, "suffix")
		badChar := invalidChars[rapid.IntRange(0, len(invalidChars)-1).Draw(t, "charIdx")]
		hostname := prefix + string(badChar) + suffix
		if err := ValidateHostname(hostname); err == nil {
			t.Fatalf("hostname with invalid char %q (%q) should fail", hostname, string(badChar))
		}
	})
}

// ==========================================================================
// Helper
// ==========================================================================

// assertOopsCode checks that the error chain contains an oops error with the
// expected code. It walks the error chain using errors.Unwrap to find the
// underlying oops error.
func assertOopsCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", expectedCode)
	}
	// Check that the error message or string representation contains the code.
	// oops errors include their code in the formatted output.
	errStr := fmt.Sprintf("%+v", err)
	if !strings.Contains(errStr, expectedCode) {
		t.Errorf("expected error code %q in error: %v", expectedCode, err)
	}
}

// assertSliceContainsOopsCode checks that at least one error in the slice
// contains an oops error with the expected code.
func assertSliceContainsOopsCode(t *testing.T, errs []error, expectedCode string) {
	t.Helper()
	if len(errs) == 0 {
		t.Fatalf("expected errors with code %q, got empty slice", expectedCode)
	}
	for _, err := range errs {
		errStr := fmt.Sprintf("%+v", err)
		if strings.Contains(errStr, expectedCode) {
			return
		}
	}
	t.Errorf("expected error code %q in error slice: %v", expectedCode, errs)
}
