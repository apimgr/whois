package rdap

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseDomainResponse(t *testing.T) {
	resp := &DomainResponse{
		ObjectClassName: "domain",
		LDHName:         "EXAMPLE.COM",
		Status:          []string{"active"},
		Nameservers: []struct {
			ObjectClassName string `json:"objectClassName"`
			LDHName         string `json:"ldhName"`
		}{
			{ObjectClassName: "nameserver", LDHName: "NS1.EXAMPLE.COM"},
			{ObjectClassName: "nameserver", LDHName: "NS2.EXAMPLE.COM"},
		},
		SecureDNS: &struct {
			DelegationSigned bool `json:"delegationSigned"`
		}{DelegationSigned: true},
		Events: []Event{
			{EventAction: "registration", EventDate: "2020-01-01T00:00:00Z"},
			{EventAction: "expiration", EventDate: "2030-01-01T00:00:00Z"},
		},
		Entities: []Entity{
			{
				Roles:      []string{"registrar"},
				VCardArray: VCardArray{"vcard", []interface{}{
					[]interface{}{"fn", struct{}{}, "text", "Test Registrar"},
				}},
				PublicIDs: []PublicID{
					{Type: "IANA Registrar ID", Identifier: "1234"},
				},
			},
			{
				Roles:      []string{"registrant"},
				VCardArray: VCardArray{"vcard", []interface{}{
					[]interface{}{"fn", struct{}{}, "text", "John Doe"},
					[]interface{}{"org", struct{}{}, "text", "Test Org"},
					[]interface{}{"email", struct{}{}, "text", "test@example.com"},
				}},
			},
		},
		Port43: "whois.example.com",
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseDomainResponse(resp, "example.com", "https://rdap.example.com/", rawJSON)

	if result.Query != "example.com" {
		t.Errorf("Query = %q, want %q", result.Query, "example.com")
	}
	if result.QueryType != "domain" {
		t.Errorf("QueryType = %q, want %q", result.QueryType, "domain")
	}
	if result.Source != "rdap" {
		t.Errorf("Source = %q, want %q", result.Source, "rdap")
	}
	if len(result.Status) != 1 || result.Status[0] != "active" {
		t.Errorf("Status = %v", result.Status)
	}
	if len(result.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", result.Nameservers)
	}
	if !result.DNSSEC {
		t.Error("DNSSEC = false, want true")
	}
	if result.CreatedDate.IsZero() {
		t.Error("CreatedDate is zero")
	}
	if result.ExpiryDate.IsZero() {
		t.Error("ExpiryDate is zero")
	}
	if result.Registrar != "Test Registrar" {
		t.Errorf("Registrar = %q", result.Registrar)
	}
	if result.RegistrarID != "1234" {
		t.Errorf("RegistrarID = %q", result.RegistrarID)
	}
	if result.RegistrantName != "John Doe" {
		t.Errorf("RegistrantName = %q", result.RegistrantName)
	}
	if result.RegistrantOrg != "Test Org" {
		t.Errorf("RegistrantOrg = %q", result.RegistrantOrg)
	}
	if result.RegistrantEmail != "test@example.com" {
		t.Errorf("RegistrantEmail = %q", result.RegistrantEmail)
	}
}

func TestParseIPResponse(t *testing.T) {
	resp := &IPResponse{
		ObjectClassName: "ip network",
		Handle:          "NET-8-0-0-0-1",
		StartAddress:    "8.0.0.0",
		EndAddress:      "8.255.255.255",
		IPVersion:       "v4",
		Name:            "GOOGLE",
		Type:            "DIRECT ALLOCATION",
		Country:         "US",
		Status:          []string{"active"},
		Events: []Event{
			{EventAction: "registration", EventDate: "2010-01-01T00:00:00Z"},
		},
		Entities: []Entity{
			{
				Roles:      []string{"registrant"},
				VCardArray: VCardArray{"vcard", []interface{}{
					[]interface{}{"org", struct{}{}, "text", "Google LLC"},
				}},
			},
		},
		Port43: "whois.arin.net",
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseIPResponse(resp, "8.8.8.8", "https://rdap.arin.net/", rawJSON, false)

	if result.Query != "8.8.8.8" {
		t.Errorf("Query = %q, want %q", result.Query, "8.8.8.8")
	}
	if result.QueryType != "ipv4" {
		t.Errorf("QueryType = %q, want %q", result.QueryType, "ipv4")
	}
	if result.NetworkName != "GOOGLE" {
		t.Errorf("NetworkName = %q", result.NetworkName)
	}
	if result.NetworkType != "DIRECT ALLOCATION" {
		t.Errorf("NetworkType = %q", result.NetworkType)
	}
	if result.NetworkRange != "8.0.0.0 - 8.255.255.255" {
		t.Errorf("NetworkRange = %q", result.NetworkRange)
	}
	if result.RegistrantCountry != "US" {
		t.Errorf("RegistrantCountry = %q", result.RegistrantCountry)
	}
	if result.RegistrantOrg != "Google LLC" {
		t.Errorf("RegistrantOrg = %q", result.RegistrantOrg)
	}
	if result.RIR != "ARIN" {
		t.Errorf("RIR = %q, want ARIN", result.RIR)
	}
}

func TestParseASNResponse(t *testing.T) {
	resp := &ASNResponse{
		ObjectClassName: "autnum",
		Handle:          "AS15169",
		StartAutnum:     15169,
		EndAutnum:       15169,
		Name:            "GOOGLE",
		Type:            "DIRECT ALLOCATION",
		Country:         "US",
		Status:          []string{"active"},
		Events: []Event{
			{EventAction: "registration", EventDate: "2000-03-01T00:00:00Z"},
		},
		Entities: []Entity{
			{
				Roles:      []string{"registrant"},
				VCardArray: VCardArray{"vcard", []interface{}{
					[]interface{}{"org", struct{}{}, "text", "Google LLC"},
				}},
			},
		},
		Port43: "whois.arin.net",
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseASNResponse(resp, 15169, "https://rdap.arin.net/", rawJSON)

	if result.Query != "AS15169" {
		t.Errorf("Query = %q, want %q", result.Query, "AS15169")
	}
	if result.QueryType != "asn" {
		t.Errorf("QueryType = %q, want %q", result.QueryType, "asn")
	}
	if result.ASNNumber != 15169 {
		t.Errorf("ASNNumber = %d", result.ASNNumber)
	}
	if result.ASNName != "GOOGLE" {
		t.Errorf("ASNName = %q", result.ASNName)
	}
	if result.RegistrantOrg != "Google LLC" {
		t.Errorf("RegistrantOrg = %q", result.RegistrantOrg)
	}
	if result.RIR != "ARIN" {
		t.Errorf("RIR = %q, want ARIN", result.RIR)
	}
}

func TestParseRDAPDate(t *testing.T) {
	tests := []struct {
		input    string
		wantYear int
	}{
		{"2020-01-15T10:30:00Z", 2020},
		{"2025-06-20T00:00:00-05:00", 2025},
		{"2018-12-01", 2018},
		{"", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		got := parseRDAPDate(tt.input)
		if tt.wantYear == 0 {
			if !got.IsZero() {
				t.Errorf("parseRDAPDate(%q) = %v, want zero", tt.input, got)
			}
		} else {
			if got.Year() != tt.wantYear {
				t.Errorf("parseRDAPDate(%q) year = %d, want %d", tt.input, got.Year(), tt.wantYear)
			}
		}
	}
}

func TestDetectRIRFromServer(t *testing.T) {
	tests := []struct {
		server string
		want   string
	}{
		{"whois.arin.net", "ARIN"},
		{"whois.ripe.net", "RIPE"},
		{"whois.apnic.net", "APNIC"},
		{"whois.lacnic.net", "LACNIC"},
		{"whois.afrinic.net", "AFRINIC"},
		{"whois.verisign.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := detectRIRFromServer(tt.server)
		if got != tt.want {
			t.Errorf("detectRIRFromServer(%q) = %q, want %q", tt.server, got, tt.want)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{-5, "-5"},
	}

	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Dummy import to ensure time is used
var _ = time.Now

// TestDetectRIRFromEndpoint covers the endpoint-based RIR detection fallback used
// in ParseIPResponse and ParseASNResponse when Port43 is empty.
func TestDetectRIRFromEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		endpoint string
		want     string
	}{
		{"https://rdap.arin.net/registry/", "ARIN"},
		{"https://rdap.db.ripe.net/", "RIPE"},
		{"https://rdap.apnic.net/", "APNIC"},
		{"https://rdap.lacnic.net/rdap/", "LACNIC"},
		{"https://rdap.afrinic.net/whois/rdap/", "AFRINIC"},
		{"https://rdap.verisign.com/com/v1/", ""},
		{"", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.endpoint, func(t *testing.T) {
			t.Parallel()
			got := detectRIRFromEndpoint(tt.endpoint)
			if got != tt.want {
				t.Errorf("detectRIRFromEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

// TestParseIPResponse_CIDR verifies the Cidr0Cidrs path in ParseIPResponse,
// which takes priority over StartAddress/EndAddress when present.
func TestParseIPResponse_CIDR(t *testing.T) {
	t.Parallel()
	resp := &IPResponse{
		ObjectClassName: "ip network",
		Name:            "ARIN-NET",
		Cidr0Cidrs: []struct {
			V4Prefix string `json:"v4prefix,omitempty"`
			V6Prefix string `json:"v6prefix,omitempty"`
			Length   int    `json:"length"`
		}{
			{V4Prefix: "8.0.0.0", Length: 8},
			{V4Prefix: "8.8.0.0", Length: 16},
		},
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseIPResponse(resp, "8.8.8.8", "https://rdap.arin.net/registry/", rawJSON, false)

	if result.QueryType != "ipv4" {
		t.Errorf("QueryType = %q, want %q", result.QueryType, "ipv4")
	}
	wantRange := "8.0.0.0/8, 8.8.0.0/16"
	if result.NetworkRange != wantRange {
		t.Errorf("NetworkRange = %q, want %q", result.NetworkRange, wantRange)
	}
	if result.RIR != "ARIN" {
		t.Errorf("RIR = %q, want ARIN (from endpoint fallback)", result.RIR)
	}
}

// TestParseIPResponse_IPv6CIDR covers the isIPv6=true path and V6Prefix CIDR
// notation.
func TestParseIPResponse_IPv6CIDR(t *testing.T) {
	t.Parallel()
	resp := &IPResponse{
		ObjectClassName: "ip network",
		Name:            "APNIC-V6",
		Cidr0Cidrs: []struct {
			V4Prefix string `json:"v4prefix,omitempty"`
			V6Prefix string `json:"v6prefix,omitempty"`
			Length   int    `json:"length"`
		}{
			{V6Prefix: "2001:4860::", Length: 32},
		},
		Port43: "whois.apnic.net",
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseIPResponse(resp, "2001:4860::1", "https://rdap.apnic.net/", rawJSON, true)

	if result.QueryType != "ipv6" {
		t.Errorf("QueryType = %q, want %q", result.QueryType, "ipv6")
	}
	wantRange := "2001:4860::/32"
	if result.NetworkRange != wantRange {
		t.Errorf("NetworkRange = %q, want %q", result.NetworkRange, wantRange)
	}
	if result.RIR != "APNIC" {
		t.Errorf("RIR = %q, want APNIC (from port43)", result.RIR)
	}
}

// TestParseVCard_OrgAsArray verifies parseVCard handles org as []interface{}
// (the jCard spec allows both string and array for the org property).
func TestParseVCard_OrgAsArray(t *testing.T) {
	t.Parallel()
	vcard := VCardArray{
		"vcard",
		[]interface{}{
			[]interface{}{"fn", struct{}{}, "text", "John Doe"},
			[]interface{}{"org", struct{}{}, "text", []interface{}{"Example Corp", "Engineering"}},
		},
	}

	name, org, _ := parseVCard(vcard)
	if name != "John Doe" {
		t.Errorf("name = %q, want %q", name, "John Doe")
	}
	if org != "Example Corp" {
		t.Errorf("org = %q, want %q (first element of array)", org, "Example Corp")
	}
}

// TestParseVCard_OrgAsArrayEmpty verifies parseVCard handles an empty org array
// without panicking.
func TestParseVCard_OrgAsArrayEmpty(t *testing.T) {
	t.Parallel()
	vcard := VCardArray{
		"vcard",
		[]interface{}{
			[]interface{}{"org", struct{}{}, "text", []interface{}{}},
		},
	}

	_, org, _ := parseVCard(vcard)
	if org != "" {
		t.Errorf("org = %q, want empty string for empty org array", org)
	}
}

// TestParseEntity_RegistrarFallbackToOrg verifies that when a registrar entity has
// no FN (name) but has an ORG, the org name is used as the registrar.
func TestParseEntity_RegistrarFallbackToOrg(t *testing.T) {
	t.Parallel()
	entity := Entity{
		Roles: []string{"registrar"},
		VCardArray: VCardArray{
			"vcard",
			[]interface{}{
				// No "fn" property — only org
				[]interface{}{"org", struct{}{}, "text", "NameCheap Inc."},
				[]interface{}{"email", struct{}{}, "text", "abuse@namecheap.com"},
			},
		},
	}

	result := &ParsedResult{}
	parseEntity(&entity, result)

	if result.Registrar != "NameCheap Inc." {
		t.Errorf("Registrar = %q, want %q (org fallback when name is empty)", result.Registrar, "NameCheap Inc.")
	}
}

// TestParseEntity_NestedEntities verifies parseEntity recurses into entity.Entities
// and sets registrar info found in a nested entity.
func TestParseEntity_NestedEntities(t *testing.T) {
	t.Parallel()
	nested := Entity{
		Roles: []string{"registrar"},
		VCardArray: VCardArray{
			"vcard",
			[]interface{}{
				[]interface{}{"fn", struct{}{}, "text", "NestedRegistrar"},
			},
		},
	}
	outer := Entity{
		Roles:    []string{"technical"},
		Entities: []Entity{nested},
	}

	result := &ParsedResult{}
	parseEntity(&outer, result)

	if result.Registrar != "NestedRegistrar" {
		t.Errorf("Registrar = %q, want %q (from nested entity)", result.Registrar, "NestedRegistrar")
	}
}

// TestParseASNResponse_EndpointRIRFallback verifies RIR detection falls back to
// the RDAP endpoint URL when Port43 is empty.
func TestParseASNResponse_EndpointRIRFallback(t *testing.T) {
	t.Parallel()
	resp := &ASNResponse{
		ObjectClassName: "autnum",
		StartAutnum:     12345,
		EndAutnum:       12345,
		Name:            "RIPE-TEST",
		// Port43 is intentionally empty
	}

	rawJSON, _ := json.Marshal(resp)
	result := ParseASNResponse(resp, 12345, "https://rdap.db.ripe.net/autnum/12345", rawJSON)

	if result.RIR != "RIPE" {
		t.Errorf("RIR = %q, want RIPE (from endpoint fallback)", result.RIR)
	}
}
