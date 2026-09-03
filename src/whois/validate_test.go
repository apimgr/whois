package whois

import (
	"strings"
	"testing"
)

// TestValidateDomain covers valid domains, invalid formats, edge-case labels,
// and RFC-required structure (minimum two labels, max label/total length).
func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid domains
		{name: "simple two-label", input: "example.com", wantErr: false},
		{name: "subdomain", input: "sub.example.co.uk", wantErr: false},
		{name: "punycode IDN", input: "xn--nxasmq6b.com", wantErr: false},
		{name: "minimal two-label", input: "a.b", wantErr: false},
		{name: "mixed alphanum labels", input: "foo123.bar456.com", wantErr: false},
		{name: "hyphen in middle", input: "my-server.example.com", wantErr: false},
		{name: "label exactly 63 chars", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", wantErr: false},

		// Invalid — empty
		{name: "empty string", input: "", wantErr: true},

		// Invalid — leading/trailing hyphen
		{name: "label leading hyphen", input: "-bad.com", wantErr: true},
		{name: "label trailing hyphen", input: "bad-.com", wantErr: true},

		// Invalid — double dot (empty label)
		{name: "double dot", input: "bad..com", wantErr: true},

		// Invalid — label exceeds 63 characters
		{name: "label 64 chars", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", wantErr: true},

		// Invalid — single label (no dot)
		{name: "single label only", input: "localhost", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateDomain(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateDomain(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestValidateIPv4 checks valid addresses, boundary octets, and reject of IPv6/malformed.
func TestValidateIPv4(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "loopback", input: "127.0.0.1", wantErr: false},
		{name: "all octets", input: "1.2.3.4", wantErr: false},
		{name: "broadcast", input: "255.255.255.255", wantErr: false},
		{name: "all zeros", input: "0.0.0.0", wantErr: false},

		// Invalid — octet out of range
		{name: "octet 256", input: "256.0.0.1", wantErr: true},

		// Invalid — too few octets
		{name: "three octets", input: "1.2.3", wantErr: true},

		// Invalid — IPv6 address
		{name: "IPv6 loopback", input: "::1", wantErr: true},

		// Invalid — empty
		{name: "empty", input: "", wantErr: true},

		// Invalid — hostname
		{name: "hostname string", input: "not-an-ip", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIPv4(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateIPv4(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateIPv4(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestValidateIPv6 checks valid compressed/expanded addresses and rejects IPv4/garbage.
func TestValidateIPv6(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "loopback", input: "::1", wantErr: false},
		{name: "Google DNS", input: "2001:4860:4860::8888", wantErr: false},
		{name: "link-local", input: "fe80::1", wantErr: false},
		{name: "full form", input: "2001:0db8:0000:0000:0000:0000:0000:0001", wantErr: false},

		// Invalid — not an IP
		{name: "hostname string", input: "not-an-ip", wantErr: true},

		// Invalid — IPv4 address (To4 != nil)
		{name: "IPv4 address", input: "999.1.1.1", wantErr: true},
		{name: "valid IPv4", input: "1.2.3.4", wantErr: true},

		// Invalid — empty
		{name: "empty", input: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIPv6(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateIPv6(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateIPv6(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestValidateASN checks prefix normalisation, valid ranges, and rejects AS0/overflow/bare numbers.
func TestValidateASN(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "Google AS uppercase", input: "AS15169", wantErr: false},
		{name: "Cloudflare AS lowercase prefix", input: "as13335", wantErr: false},
		{name: "minimal AS number", input: "AS1", wantErr: false},
		{name: "max 32-bit ASN", input: "AS4294967295", wantErr: false},

		// Invalid — empty
		{name: "empty", input: "", wantErr: true},

		// ValidateASN strips the "AS" prefix before parsing, so a bare number
		// is also accepted — the AS prefix is optional in the validator.
		{name: "bare number accepted", input: "15169", wantErr: false},

		// Invalid — AS0
		{name: "AS zero", input: "AS0", wantErr: true},

		// Invalid — exceeds 32-bit range
		{name: "AS exceeds 32-bit", input: "AS4294967296", wantErr: true},

		// Invalid — non-numeric after prefix
		{name: "non-numeric suffix", input: "ASabc", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateASN(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateASN(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateASN(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestValidateQuery exercises the dispatch logic: each query type should route
// to the correct underlying validator and return nil on valid input / error on invalid.
func TestValidateQuery(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid domain", input: "example.com", wantErr: false},
		{name: "valid IPv4", input: "8.8.8.8", wantErr: false},
		{name: "valid IPv6", input: "2001:4860:4860::8888", wantErr: false},
		{name: "valid ASN", input: "AS15169", wantErr: false},

		// Unknown type should error
		{name: "unknown type empty", input: "", wantErr: true},
		{name: "unknown type gibberish", input: "!!!!", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateQuery(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateQuery(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateQuery(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestDetectQueryType verifies the classifier returns the correct WHOISQueryType
// for representative inputs of every category.
func TestDetectQueryType(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  WHOISQueryType
	}{
		{name: "domain", input: "example.com", want: QueryTypeDomain},
		{name: "IPv4", input: "8.8.8.8", want: QueryTypeIPv4},
		{name: "IPv6", input: "2001:4860::1", want: QueryTypeIPv6},
		{name: "ASN uppercase", input: "AS15169", want: QueryTypeASN},
		{name: "ASN lowercase", input: "as13335", want: QueryTypeASN},

		// Whitespace trimming — should still classify correctly
		{name: "domain with leading space", input: " example.com", want: QueryTypeDomain},

		// Unknown
		{name: "empty string", input: "", want: QueryTypeUnknown},
		{name: "special chars", input: "!!!!", want: QueryTypeUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectQueryType(tc.input)
			if got != tc.want {
				t.Errorf("DetectQueryType(%q) = %v (%d), want %v (%d)",
					tc.input, got, got, tc.want, tc.want)
			}
		})
	}
}

// TestValidationErrorMessage verifies that ValidationError.Error() formats the
// field and message correctly.
func TestValidationErrorMessage(t *testing.T) {
	e := ValidationError{Field: "domain", Message: "cannot be empty"}
	got := e.Error()
	want := "domain: cannot be empty"
	if got != want {
		t.Errorf("ValidationError.Error() = %q, want %q", got, want)
	}
}

// TestValidateDomainMaxLength ensures a ≤253-character domain is accepted and
// a 254-character domain is rejected.
func TestValidateDomainMaxLength(t *testing.T) {
	// Each label is at most 63 chars. Total domain ≤ 253 chars.
	// Build exactly 253 chars: four labels separated by dots.
	// Pattern: 63 + "." + 63 + "." + 63 + "." + 61 = 63+1+63+1+63+1+61 = 253
	label63 := strings.Repeat("a", 63)
	label61 := strings.Repeat("b", 61)
	valid253 := label63 + "." + label63 + "." + label63 + "." + label61
	if len(valid253) != 253 {
		t.Fatalf("test setup error: valid253 is %d chars, want 253", len(valid253))
	}
	if err := ValidateDomain(valid253); err != nil {
		t.Errorf("ValidateDomain(253-char domain) unexpected error: %v", err)
	}

	// 254 chars: extend the last label by one character.
	label62 := strings.Repeat("b", 62)
	over253 := label63 + "." + label63 + "." + label63 + "." + label62
	if len(over253) != 254 {
		t.Fatalf("test setup error: over253 is %d chars, want 254", len(over253))
	}
	if err := ValidateDomain(over253); err == nil {
		t.Errorf("ValidateDomain(%d-char domain) expected error, got nil", len(over253))
	}
}
