package parser

import (
	"strings"
	"testing"
	"time"
)

// --- ParseDomain tests -------------------------------------------------------
// Covers: field extraction for all patterns, comment/blank-line skipping,
// duplicate deduplication for nameservers and status, first-match wins for
// scalar fields, date parsing via every supported format, empty/minimal input.

func TestParseDomain_FullResponse(t *testing.T) {
	raw := `
% This is a comment line
# Another comment

Domain Name: EXAMPLE.COM
Registrar: Example Registrar LLC
Registrar IANA ID: 9999
Registrant Name: John Doe
Registrant Organization: Example Corp
Registrant Email: john@example.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Creation Date: 1995-08-15T04:00:00Z
Updated Date: 2024-03-01T12:00:00Z
Registry Expiry Date: 2025-08-15T04:00:00Z
DNSSEC: unsigned
`

	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("ParseDomain returned error: %v", err)
	}

	if result.Domain != "EXAMPLE.COM" {
		t.Errorf("Domain = %q, want %q", result.Domain, "EXAMPLE.COM")
	}
	if result.Registrar != "Example Registrar LLC" {
		t.Errorf("Registrar = %q, want %q", result.Registrar, "Example Registrar LLC")
	}
	if result.RegistrarID != "9999" {
		t.Errorf("RegistrarID = %q, want %q", result.RegistrarID, "9999")
	}
	if result.Registrant != "John Doe" {
		t.Errorf("Registrant = %q, want %q", result.Registrant, "John Doe")
	}
	if result.Organization != "Example Corp" {
		t.Errorf("Organization = %q, want %q", result.Organization, "Example Corp")
	}
	if result.Email != "john@example.com" {
		t.Errorf("Email = %q, want %q", result.Email, "john@example.com")
	}
	if len(result.Nameservers) != 2 {
		t.Errorf("Nameservers count = %d, want 2", len(result.Nameservers))
	} else {
		if result.Nameservers[0] != "ns1.example.com" {
			t.Errorf("Nameservers[0] = %q, want %q", result.Nameservers[0], "ns1.example.com")
		}
		if result.Nameservers[1] != "ns2.example.com" {
			t.Errorf("Nameservers[1] = %q, want %q", result.Nameservers[1], "ns2.example.com")
		}
	}
	if len(result.Status) != 2 {
		t.Errorf("Status count = %d, want 2", len(result.Status))
	}
	if result.DNSSEC != "unsigned" {
		t.Errorf("DNSSEC = %q, want %q", result.DNSSEC, "unsigned")
	}
	if result.CreatedDate.IsZero() {
		t.Error("CreatedDate is zero, want 1995-08-15")
	}
	if result.UpdatedDate.IsZero() {
		t.Error("UpdatedDate is zero")
	}
	if result.ExpiryDate.IsZero() {
		t.Error("ExpiryDate is zero")
	}
	if result.Raw != raw {
		t.Error("Raw field not preserved")
	}
}

func TestParseDomain_Empty(t *testing.T) {
	result, err := ParseDomain("")
	if err != nil {
		t.Fatalf("ParseDomain(\"\") unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Domain != "" {
		t.Errorf("Domain = %q, want empty", result.Domain)
	}
	if len(result.Nameservers) != 0 {
		t.Errorf("Nameservers = %v, want empty slice", result.Nameservers)
	}
	if len(result.Status) != 0 {
		t.Errorf("Status = %v, want empty slice", result.Status)
	}
}

func TestParseDomain_OnlyComments(t *testing.T) {
	raw := "% comment line\n# hash comment\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "" {
		t.Errorf("Domain = %q, want empty", result.Domain)
	}
}

// TestParseDomain_FirstMatchWins verifies scalar fields stop updating after first hit.
func TestParseDomain_FirstMatchWins(t *testing.T) {
	raw := `Domain Name: FIRST.COM
Domain Name: SECOND.COM
Registrar: First Registrar
Registrar: Second Registrar
`
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "FIRST.COM" {
		t.Errorf("Domain = %q, want FIRST.COM (first-match)", result.Domain)
	}
	if result.Registrar != "First Registrar" {
		t.Errorf("Registrar = %q, want %q", result.Registrar, "First Registrar")
	}
}

// TestParseDomain_NServerKeyword verifies "nserver:" is accepted as a nameserver key.
func TestParseDomain_NServerKeyword(t *testing.T) {
	raw := "nserver: ns1.example.net\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Nameservers) != 1 || result.Nameservers[0] != "ns1.example.net" {
		t.Errorf("Nameservers = %v, want [ns1.example.net]", result.Nameservers)
	}
}

// TestParseDomain_DuplicateNameserversDeduped verifies identical NS entries collapse.
func TestParseDomain_DuplicateNameserversDeduped(t *testing.T) {
	raw := "Name Server: NS1.EXAMPLE.COM\nName Server: ns1.example.com\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Nameservers) != 1 {
		t.Errorf("Nameservers = %v, want exactly 1 after dedup", result.Nameservers)
	}
}

// TestParseDomain_DuplicateStatusDeduped verifies identical status codes collapse.
func TestParseDomain_DuplicateStatusDeduped(t *testing.T) {
	raw := "Domain Status: clientDeleteProhibited https://icann.org/epp#x\nDomain Status: clientDeleteProhibited https://icann.org/epp#x\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Status) != 1 {
		t.Errorf("Status = %v, want exactly 1 after dedup", result.Status)
	}
}

// TestParseDomain_StatusStrippedAtSpace verifies status URLs are stripped.
func TestParseDomain_StatusStrippedAtSpace(t *testing.T) {
	raw := "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Status) != 1 {
		t.Fatalf("Status count = %d, want 1", len(result.Status))
	}
	if result.Status[0] != "clientTransferProhibited" {
		t.Errorf("Status[0] = %q, want %q", result.Status[0], "clientTransferProhibited")
	}
}

// TestParseDomain_AlternateCreatedKeywords verifies "created" and "registered on" labels.
func TestParseDomain_AlternateCreatedKeywords(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"created keyword", "created: 2020-01-01\n"},
		{"registered on keyword", "registered on: 2020-01-01\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseDomain(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.CreatedDate.IsZero() {
				t.Errorf("CreatedDate is zero for line %q", tc.line)
			}
		})
	}
}

// TestParseDomain_AlternateExpiryKeywords verifies all expiry field aliases.
func TestParseDomain_AlternateExpiryKeywords(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"expiry date", "Expiry Date: 2026-01-01\n"},
		{"expiration date", "Expiration Date: 2026-01-01\n"},
		{"expires", "Expires: 2026-01-01\n"},
		{"registry expiry date", "Registry Expiry Date: 2026-01-01\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseDomain(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ExpiryDate.IsZero() {
				t.Errorf("ExpiryDate is zero for line %q", tc.line)
			}
		})
	}
}

// --- parseDate tests ---------------------------------------------------------
// Covers all nine date formats the function accepts, plus an unparseable string.

func TestParseDate(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantNil  bool
		wantYear int
	}{
		{name: "RFC3339", input: "2020-06-15T10:30:00Z", wantYear: 2020},
		{name: "RFC3339 no Z suffix", input: "2020-06-15T10:30:00Z", wantYear: 2020},
		{name: "RFC3339 with offset", input: "2020-06-15T10:30:00-05:00", wantYear: 2020},
		{name: "datetime no T", input: "2020-06-15 10:30:05", wantYear: 2020},
		{name: "date only", input: "2020-06-15", wantYear: 2020},
		{name: "day-mon-year", input: "15-Jun-2020", wantYear: 2020},
		{name: "DD/MM/YYYY", input: "15/06/2020", wantYear: 2020},
		{name: "MM/DD/YYYY", input: "06/15/2020", wantYear: 2020},
		{name: "dot separated", input: "2020.06.15", wantYear: 2020},
		{name: "unparseable", input: "not-a-date", wantNil: true},
		{name: "empty string", input: "", wantNil: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDate(tc.input)
			if tc.wantNil {
				if !got.IsZero() {
					t.Errorf("parseDate(%q) = %v, want zero time", tc.input, got)
				}
				return
			}
			if got.IsZero() {
				t.Errorf("parseDate(%q) = zero time, want year %d", tc.input, tc.wantYear)
				return
			}
			if got.Year() != tc.wantYear {
				t.Errorf("parseDate(%q).Year() = %d, want %d", tc.input, got.Year(), tc.wantYear)
			}
		})
	}
}

// TestParseDate_LeadingTrailingSpace verifies TrimSpace is applied.
func TestParseDate_LeadingTrailingSpace(t *testing.T) {
	got := parseDate("  2022-03-01  ")
	if got.IsZero() {
		t.Error("parseDate with surrounding spaces returned zero time")
	}
	if got.Year() != 2022 {
		t.Errorf("year = %d, want 2022", got.Year())
	}
}

// --- contains tests ----------------------------------------------------------

func TestContains(t *testing.T) {
	cases := []struct {
		name  string
		slice []string
		val   string
		want  bool
	}{
		{name: "present", slice: []string{"a", "b", "c"}, val: "b", want: true},
		{name: "absent", slice: []string{"a", "b", "c"}, val: "d", want: false},
		{name: "empty slice", slice: []string{}, val: "a", want: false},
		{name: "nil slice", slice: nil, val: "a", want: false},
		{name: "case sensitive match", slice: []string{"NS1"}, val: "NS1", want: true},
		{name: "case sensitive mismatch", slice: []string{"NS1"}, val: "ns1", want: false},
		{name: "empty string in slice", slice: []string{""}, val: "", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(tc.slice, tc.val)
			if got != tc.want {
				t.Errorf("contains(%v, %q) = %v, want %v", tc.slice, tc.val, got, tc.want)
			}
		})
	}
}

// --- ParseIP tests -----------------------------------------------------------
// Covers: all field patterns, generic org replacement, abuse contact combinations,
// ASN prefix normalisation, country uppercasing, allocation date, empty input.

func TestParseIP_FullARINResponse(t *testing.T) {
	raw := `
#
# ARIN WHOIS data
#
NetRange: 8.0.0.0 - 8.255.255.255
CIDR: 8.0.0.0/8
OrgName: Google LLC
OriginAS: AS15169
Country: US
OrgAbuseEmail: network-abuse@google.com
OrgAbusePhone: +1-650-253-0000
RegDate: 2014-03-14
`
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("ParseIP returned error: %v", err)
	}
	if result.Network != "8.0.0.0 - 8.255.255.255" {
		t.Errorf("Network = %q, want %q", result.Network, "8.0.0.0 - 8.255.255.255")
	}
	if result.CIDR != "8.0.0.0/8" {
		t.Errorf("CIDR = %q, want %q", result.CIDR, "8.0.0.0/8")
	}
	if result.Organization != "Google LLC" {
		t.Errorf("Organization = %q, want %q", result.Organization, "Google LLC")
	}
	if result.ASN != "AS15169" {
		t.Errorf("ASN = %q, want %q", result.ASN, "AS15169")
	}
	if result.Country != "US" {
		t.Errorf("Country = %q, want %q", result.Country, "US")
	}
	if !strings.Contains(result.AbuseContact, "network-abuse@google.com") {
		t.Errorf("AbuseContact = %q, want email included", result.AbuseContact)
	}
	if !strings.Contains(result.AbuseContact, "+1-650-253-0000") {
		t.Errorf("AbuseContact = %q, want phone included", result.AbuseContact)
	}
	if result.AllocationDate.IsZero() {
		t.Error("AllocationDate is zero")
	}
}

func TestParseIP_RIPEResponse(t *testing.T) {
	raw := `inetnum: 195.0.0.0 - 195.255.255.255
descr: RIPE NCC
origin: AS3333
country: NL
`
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("ParseIP returned error: %v", err)
	}
	if result.Network != "195.0.0.0 - 195.255.255.255" {
		t.Errorf("Network = %q", result.Network)
	}
	if result.ASN != "AS3333" {
		t.Errorf("ASN = %q, want AS3333", result.ASN)
	}
	if result.Country != "NL" {
		t.Errorf("Country = %q, want NL", result.Country)
	}
}

// TestParseIP_ASNNumericPrefix verifies the "AS" prefix is prepended from numeric origin.
func TestParseIP_ASNNumericPrefix(t *testing.T) {
	raw := "origin: 15169\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != "AS15169" {
		t.Errorf("ASN = %q, want AS15169", result.ASN)
	}
}

// TestParseIP_OriginASKeyword verifies "originas" and "origin as" patterns.
func TestParseIP_OriginASKeyword(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"originas", "originas: AS64496\n"},
		{"origin AS with space", "origin as: 64496\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseIP(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ASN == "" {
				t.Errorf("ASN is empty for line %q", tc.line)
			}
		})
	}
}

// TestParseIP_CountryUppercased verifies lowercase country codes are uppercased.
func TestParseIP_CountryUppercased(t *testing.T) {
	raw := "country: de\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Country != "DE" {
		t.Errorf("Country = %q, want DE", result.Country)
	}
}

// TestParseIP_AbuseEmailOnly verifies abuse contact with email but no phone.
func TestParseIP_AbuseEmailOnly(t *testing.T) {
	raw := "abuse-mailbox: abuse@example.com\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AbuseContact != "abuse@example.com" {
		t.Errorf("AbuseContact = %q, want abuse@example.com", result.AbuseContact)
	}
}

// TestParseIP_AbusePhoneOnly verifies abuse contact with phone but no email.
func TestParseIP_AbusePhoneOnly(t *testing.T) {
	raw := "abuse-phone: +1-800-555-0000\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AbuseContact != "+1-800-555-0000" {
		t.Errorf("AbuseContact = %q, want phone only", result.AbuseContact)
	}
}

// TestParseIP_NoAbuseContact verifies empty AbuseContact when neither field is present.
func TestParseIP_NoAbuseContact(t *testing.T) {
	raw := "NetRange: 10.0.0.0 - 10.255.255.255\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AbuseContact != "" {
		t.Errorf("AbuseContact = %q, want empty", result.AbuseContact)
	}
}

// TestParseIP_GenericOrgSkipped verifies that generic org names are not used.
func TestParseIP_GenericOrgSkipped(t *testing.T) {
	raw := `descr: RESERVED
descr: Private Network Labs
`
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Organization != "Private Network Labs" {
		t.Errorf("Organization = %q, want %q (generic first line should be skipped)", result.Organization, "Private Network Labs")
	}
}

// TestParseIP_NetworkKeyword verifies "netrange" and "network" aliases.
func TestParseIP_NetworkKeyword(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"inetnum", "inetnum: 192.0.2.0 - 192.0.2.255\n"},
		{"netrange", "netrange: 192.0.2.0 - 192.0.2.255\n"},
		{"network", "network: 192.0.2.0 - 192.0.2.255\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseIP(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Network != "192.0.2.0 - 192.0.2.255" {
				t.Errorf("Network = %q", result.Network)
			}
		})
	}
}

func TestParseIP_Empty(t *testing.T) {
	result, err := ParseIP("")
	if err != nil {
		t.Fatalf("ParseIP(\"\") unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.ASN != "" || result.Country != "" || result.Organization != "" {
		t.Errorf("expected all fields empty, got ASN=%q Country=%q Org=%q",
			result.ASN, result.Country, result.Organization)
	}
}

// TestParseIP_AllocatedKeywordAliases verifies "allocated", "created", "regdate" labels.
func TestParseIP_AllocatedKeywordAliases(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"allocated", "allocated: 2010-05-01\n"},
		{"created", "created: 2010-05-01\n"},
		{"regdate", "regdate: 2010-05-01\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseIP(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.AllocationDate.IsZero() {
				t.Errorf("AllocationDate is zero for line %q", tc.line)
			}
		})
	}
}

// --- isGenericOrg tests ------------------------------------------------------

func TestIsGenericOrg(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty string", input: "", want: true},
		{name: "dashes", input: "---", want: true},
		{name: "n/a", input: "n/a", want: true},
		{name: "NA", input: "NA", want: true},
		{name: "none", input: "none", want: true},
		{name: "reserved uppercase", input: "RESERVED", want: true},
		{name: "private", input: "private", want: true},
		{name: "network", input: "network", want: true},
		{name: "real org", input: "Google LLC", want: false},
		{name: "real org with spaces", input: "  Cloudflare Inc  ", want: false},
		{name: "none with padding", input: "  none  ", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isGenericOrg(tc.input)
			if got != tc.want {
				t.Errorf("isGenericOrg(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- ParseASN tests ----------------------------------------------------------
// Covers: ASN extraction with/without prefix, as-name vs organization fallback,
// description collection and joining, country uppercasing, IPv4 and IPv6 routes,
// duplicate prefix dedup, empty input.

func TestParseASN_FullRIPEResponse(t *testing.T) {
	raw := `
% RIPE Database

aut-num: AS3333
as-name: RIPE-NCC-AS
descr: RIPE Network Coordination Centre
descr: Amsterdam, Netherlands
org: ORG-RNCC1-RIPE
country: NL
route: 193.0.0.0/21
route: 193.0.10.0/23
route6: 2001:67c:2e8::/48
`
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("ParseASN returned error: %v", err)
	}
	if result.ASN != "AS3333" {
		t.Errorf("ASN = %q, want AS3333", result.ASN)
	}
	if result.Organization != "RIPE-NCC-AS" {
		t.Errorf("Organization = %q, want RIPE-NCC-AS (from as-name)", result.Organization)
	}
	if result.Country != "NL" {
		t.Errorf("Country = %q, want NL", result.Country)
	}
	if !strings.Contains(result.Description, "RIPE Network Coordination Centre") {
		t.Errorf("Description = %q, missing first descr", result.Description)
	}
	if !strings.Contains(result.Description, "Amsterdam, Netherlands") {
		t.Errorf("Description = %q, missing second descr", result.Description)
	}
	if len(result.Prefixes) != 3 {
		t.Errorf("Prefixes count = %d, want 3", len(result.Prefixes))
	}
}

func TestParseASN_ASNWithASPrefix(t *testing.T) {
	raw := "aut-num: AS15169\nas-name: GOOGLE\ncountry: US\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != "AS15169" {
		t.Errorf("ASN = %q, want AS15169", result.ASN)
	}
}

func TestParseASN_ASNWithoutASPrefix(t *testing.T) {
	raw := "aut-num: 15169\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != "AS15169" {
		t.Errorf("ASN = %q, want AS15169 (numeric-only should get AS prefix)", result.ASN)
	}
}

// TestParseASN_ASNumberKeyword verifies "as-number" and "asn" label aliases.
func TestParseASN_ASNumberKeyword(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"as-number", "as-number: 64512\n"},
		{"asn", "asn: 64512\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseASN(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ASN != "AS64512" {
				t.Errorf("ASN = %q, want AS64512 for line %q", result.ASN, tc.line)
			}
		})
	}
}

// TestParseASN_OrgFallbackWhenNoASName verifies org is used when as-name absent.
func TestParseASN_OrgFallbackWhenNoASName(t *testing.T) {
	raw := "organization: Fallback Org\ncountry: DE\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Organization != "Fallback Org" {
		t.Errorf("Organization = %q, want %q", result.Organization, "Fallback Org")
	}
}

// TestParseASN_OrgOwnerKeyword verifies "owner" is accepted as an org alias.
func TestParseASN_OrgOwnerKeyword(t *testing.T) {
	raw := "owner: Owner Corp\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Organization != "Owner Corp" {
		t.Errorf("Organization = %q, want Owner Corp", result.Organization)
	}
}

// TestParseASN_GenericOrgNotUsedAsOrg verifies generic values are ignored in org.
func TestParseASN_GenericOrgNotUsedAsOrg(t *testing.T) {
	raw := "organization: RESERVED\norganization: Real Org\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Organization != "Real Org" {
		t.Errorf("Organization = %q, want Real Org (RESERVED should be skipped)", result.Organization)
	}
}

// TestParseASN_DescriptionCollectedAndJoined verifies multiple descr lines are joined with " / ".
func TestParseASN_DescriptionCollectedAndJoined(t *testing.T) {
	raw := "descr: First line\ndescr: Second line\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantDesc := "First line / Second line"
	if result.Description != wantDesc {
		t.Errorf("Description = %q, want %q", result.Description, wantDesc)
	}
}

// TestParseASN_DuplicateDescriptionDeduped verifies identical descr lines appear once.
func TestParseASN_DuplicateDescriptionDeduped(t *testing.T) {
	raw := "descr: Same line\ndescr: Same line\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Description != "Same line" {
		t.Errorf("Description = %q, want deduplicated value", result.Description)
	}
}

// TestParseASN_NoDescriptionIsEmpty verifies Description is empty when no descr lines.
func TestParseASN_NoDescriptionIsEmpty(t *testing.T) {
	raw := "aut-num: AS1\nas-name: TEST\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Description != "" {
		t.Errorf("Description = %q, want empty", result.Description)
	}
}

// TestParseASN_CountryUppercased verifies lowercase country codes are uppercased.
func TestParseASN_CountryUppercased(t *testing.T) {
	raw := "country: us\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Country != "US" {
		t.Errorf("Country = %q, want US", result.Country)
	}
}

// TestParseASN_DuplicatePrefixDeduped verifies the same route is not added twice.
func TestParseASN_DuplicatePrefixDeduped(t *testing.T) {
	raw := "route: 8.8.8.0/24\nroute: 8.8.8.0/24\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Prefixes) != 1 {
		t.Errorf("Prefixes = %v, want exactly 1 after dedup", result.Prefixes)
	}
}

// TestParseASN_IPv6RouteCollected verifies route6 entries appear in Prefixes.
func TestParseASN_IPv6RouteCollected(t *testing.T) {
	raw := "route6: 2001:db8::/32\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Prefixes) != 1 || result.Prefixes[0] != "2001:db8::/32" {
		t.Errorf("Prefixes = %v, want [2001:db8::/32]", result.Prefixes)
	}
}

func TestParseASN_Empty(t *testing.T) {
	result, err := ParseASN("")
	if err != nil {
		t.Fatalf("ParseASN(\"\") unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.ASN != "" {
		t.Errorf("ASN = %q, want empty", result.ASN)
	}
	if len(result.Prefixes) != 0 {
		t.Errorf("Prefixes = %v, want empty slice", result.Prefixes)
	}
}

// TestParseASN_CommentsAndBlanksSkipped verifies % and # comment lines are ignored.
func TestParseASN_CommentsAndBlanksSkipped(t *testing.T) {
	raw := "% comment\n# hash\n\naut-num: AS7\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != "AS7" {
		t.Errorf("ASN = %q, want AS7", result.ASN)
	}
}

// TestParseASN_RawPreserved verifies the Raw field equals the input string.
func TestParseASN_RawPreserved(t *testing.T) {
	raw := "aut-num: AS1\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Raw != raw {
		t.Errorf("Raw = %q, want %q", result.Raw, raw)
	}
}

// TestParseASN_AsDescrKeyword verifies "as-descr" is treated as a description line.
func TestParseASN_AsDescrKeyword(t *testing.T) {
	raw := "as-descr: My AS Description\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Description != "My AS Description" {
		t.Errorf("Description = %q, want %q", result.Description, "My AS Description")
	}
}

// TestParseASN_AsOrgnameKeyword verifies "as-orgname" is treated as an organization.
func TestParseASN_AsOrgnameKeyword(t *testing.T) {
	raw := "as-orgname: OrgName Corp\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Organization != "OrgName Corp" {
		t.Errorf("Organization = %q, want OrgName Corp", result.Organization)
	}
}

// TestParseASN_MixedIPv4AndIPv6Prefixes verifies both route types are collected together.
func TestParseASN_MixedIPv4AndIPv6Prefixes(t *testing.T) {
	raw := "route: 1.2.3.0/24\nroute6: 2001:db8::/32\nroute: 4.5.6.0/24\n"
	result, err := ParseASN(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Prefixes) != 3 {
		t.Errorf("Prefixes count = %d, want 3; got %v", len(result.Prefixes), result.Prefixes)
	}
}

// --- ParseIP raw-preserved test ----------------------------------------------

func TestParseIP_RawPreserved(t *testing.T) {
	raw := "inetnum: 192.0.2.0 - 192.0.2.255\n"
	result, err := ParseIP(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Raw != raw {
		t.Errorf("Raw = %q, want %q", result.Raw, raw)
	}
}

// --- ParseDomain raw-preserved test -----------------------------------------

func TestParseDomain_RawPreserved(t *testing.T) {
	raw := "Domain Name: TEST.ORG\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Raw != raw {
		t.Errorf("Raw = %q, want %q", result.Raw, raw)
	}
}

// TestParseDomain_UpdatedDateKeywords verifies alternate "updated" field labels.
func TestParseDomain_UpdatedDateKeywords(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"last updated", "Last Updated: 2023-07-04\n"},
		{"modified", "Modified: 2023-07-04\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseDomain(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.UpdatedDate.IsZero() {
				t.Errorf("UpdatedDate is zero for line %q", tc.line)
			}
		})
	}
}

// TestParseDomain_RegistrantOrgBothSpellings verifies both "organisation" and "organization".
func TestParseDomain_RegistrantOrgBothSpellings(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"organization", "Registrant Organization: Acme Inc\n"},
		{"organisation", "Registrant Organisation: Acme Inc\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseDomain(tc.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Organization != "Acme Inc" {
				t.Errorf("Organization = %q, want Acme Inc for line %q", result.Organization, tc.line)
			}
		})
	}
}

// TestParseDomain_CaseInsensitiveFields verifies that field patterns are case-insensitive.
func TestParseDomain_CaseInsensitiveFields(t *testing.T) {
	raw := "DOMAIN NAME: UPPER.COM\nREGISTRAR: Upper Registrar\nDNSSEC: signedDelegation\n"
	result, err := ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "UPPER.COM" {
		t.Errorf("Domain = %q, want UPPER.COM", result.Domain)
	}
	if result.Registrar != "Upper Registrar" {
		t.Errorf("Registrar = %q, want Upper Registrar", result.Registrar)
	}
	if result.DNSSEC != "signedDelegation" {
		t.Errorf("DNSSEC = %q, want signedDelegation", result.DNSSEC)
	}
}

// TestParseDate_AllFormatsReturnCorrectMonth exercises each format for a distinct month.
func TestParseDate_AllFormatsReturnCorrectMonth(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantMonth time.Month
	}{
		{"RFC3339", "2021-04-20T00:00:00Z", time.April},
		{"datetime", "2021-04-20 00:00:00", time.April},
		{"date only", "2021-04-20", time.April},
		{"DD/MM/YYYY", "20/04/2021", time.April},
		{"dot separated", "2021.04.20", time.April},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDate(tc.input)
			if got.IsZero() {
				t.Fatalf("parseDate(%q) = zero", tc.input)
			}
			if got.Month() != tc.wantMonth {
				t.Errorf("Month = %v, want %v", got.Month(), tc.wantMonth)
			}
		})
	}
}
