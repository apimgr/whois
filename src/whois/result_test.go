package whois

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/apimgr/whois/src/whois/parser"
	"github.com/apimgr/whois/src/whois/rdap"
)

func TestFromRDAPDomain(t *testing.T) {
	parsed := &rdap.ParsedResult{
		Query:           "example.com",
		QueryType:       "domain",
		Source:          "rdap",
		RDAPServer:      "https://rdap.example.com/",
		RegistrantName:  "John Doe",
		RegistrantOrg:   "Test Org",
		RegistrantEmail: "test@example.com",
		Registrar:       "Test Registrar",
		RegistrarID:     "1234",
		CreatedDate:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiryDate:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Nameservers:     []string{"ns1.example.com", "ns2.example.com"},
		Status:          []string{"active"},
		DNSSEC:          true,
		RawRDAP:         json.RawMessage(`{}`),
	}

	result := FromRDAPDomain(parsed)

	if result.Query != "example.com" {
		t.Errorf("Query = %q", result.Query)
	}
	if result.QueryType != QueryTypeDomain {
		t.Errorf("QueryType = %v", result.QueryType)
	}
	if result.Source != SourceRDAP {
		t.Errorf("Source = %q", result.Source)
	}
	if result.RegistrantName != "John Doe" {
		t.Errorf("RegistrantName = %q", result.RegistrantName)
	}
	if result.DNSSEC != "signedDelegation" {
		t.Errorf("DNSSEC = %q, want signedDelegation", result.DNSSEC)
	}
	if len(result.Nameservers) != 2 {
		t.Errorf("Nameservers = %v", result.Nameservers)
	}
}

func TestFromRDAPDomain_Unsigned(t *testing.T) {
	parsed := &rdap.ParsedResult{
		Query:     "example.com",
		QueryType: "domain",
		DNSSEC:    false,
	}

	result := FromRDAPDomain(parsed)

	if result.DNSSEC != "unsigned" {
		t.Errorf("DNSSEC = %q, want unsigned", result.DNSSEC)
	}
}

func TestFromRDAPIP(t *testing.T) {
	parsed := &rdap.ParsedResult{
		Query:             "8.8.8.8",
		QueryType:         "ipv4",
		Source:            "rdap",
		RDAPServer:        "https://rdap.arin.net/",
		RegistrantOrg:     "Google LLC",
		RegistrantCountry: "US",
		NetworkName:       "GOOGLE",
		NetworkRange:      "8.0.0.0 - 8.255.255.255",
		NetworkType:       "DIRECT ALLOCATION",
		RIR:               "ARIN",
	}

	result := FromRDAPIP(parsed, QueryTypeIPv4)

	if result.Query != "8.8.8.8" {
		t.Errorf("Query = %q", result.Query)
	}
	if result.QueryType != QueryTypeIPv4 {
		t.Errorf("QueryType = %v", result.QueryType)
	}
	if result.NetworkName != "GOOGLE" {
		t.Errorf("NetworkName = %q", result.NetworkName)
	}
	if result.RIR != "ARIN" {
		t.Errorf("RIR = %q", result.RIR)
	}
}

func TestFromRDAPASN(t *testing.T) {
	parsed := &rdap.ParsedResult{
		Query:         "AS15169",
		QueryType:     "asn",
		Source:        "rdap",
		ASNNumber:     15169,
		ASNName:       "GOOGLE",
		RegistrantOrg: "Google LLC",
		RIR:           "ARIN",
	}

	result := FromRDAPASN(parsed)

	if result.ASNNumber != 15169 {
		t.Errorf("ASNNumber = %d", result.ASNNumber)
	}
	if result.ASNName != "GOOGLE" {
		t.Errorf("ASNName = %q", result.ASNName)
	}
}

func TestFromWHOISDomain(t *testing.T) {
	parsed := &parser.DomainResult{
		Registrant: "John Doe",
		Registrar:  "Test Registrar",
		Status:     []string{"clientTransferProhibited"},
		DNSSEC:     "unsigned",
		Raw:        "Domain: example.com",
	}

	result := FromWHOISDomain(parsed, "example.com", "whois.verisign.com")

	if result.Source != SourceWHOIS {
		t.Errorf("Source = %q", result.Source)
	}
	if result.WHOISServer != "whois.verisign.com" {
		t.Errorf("WHOISServer = %q", result.WHOISServer)
	}
	if result.RDAPServer != "" {
		t.Errorf("RDAPServer = %q, want empty", result.RDAPServer)
	}
}

func TestFromWHOISIP(t *testing.T) {
	parsed := &parser.IPResult{
		IP:           "8.8.8.8",
		Network:      "GOOGLE",
		CIDR:         "8.0.0.0/8",
		Organization: "Google LLC",
		Country:      "US",
		ASN:          "AS15169",
		Raw:          "NetRange: 8.0.0.0 - 8.255.255.255",
	}

	result := FromWHOISIP(parsed, "8.8.8.8", "whois.arin.net", QueryTypeIPv4)

	if result.Source != SourceWHOIS {
		t.Errorf("Source = %q", result.Source)
	}
	if result.ASNNumber != 15169 {
		t.Errorf("ASNNumber = %d, want 15169", result.ASNNumber)
	}
	if result.RIR != "ARIN" {
		t.Errorf("RIR = %q, want ARIN", result.RIR)
	}
}

func TestFromWHOISASN(t *testing.T) {
	parsed := &parser.ASNResult{
		ASN:          "AS15169",
		Description:  "GOOGLE - Google LLC",
		Organization: "Google LLC",
		Country:      "US",
		Raw:          "ASNumber: 15169",
	}

	result := FromWHOISASN(parsed, "AS15169", "whois.arin.net")

	if result.ASNNumber != 15169 {
		t.Errorf("ASNNumber = %d", result.ASNNumber)
	}
	if result.ASNName != "GOOGLE - Google LLC" {
		t.Errorf("ASNName = %q", result.ASNName)
	}
}

func TestDetectRIRFromWHOISServer(t *testing.T) {
	tests := []struct {
		server string
		want   string
	}{
		{"whois.arin.net:43", "ARIN"},
		{"whois.ripe.net:43", "RIPE"},
		{"whois.apnic.net:43", "APNIC"},
		{"whois.lacnic.net:43", "LACNIC"},
		{"whois.afrinic.net:43", "AFRINIC"},
		{"whois.verisign.com:43", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := detectRIRFromWHOISServer(tt.server)
		if got != tt.want {
			t.Errorf("detectRIRFromWHOISServer(%q) = %q, want %q", tt.server, got, tt.want)
		}
	}
}

func TestUnifiedResult_JSON(t *testing.T) {
	result := &UnifiedResult{
		Query:     "example.com",
		QueryType: QueryTypeDomain,
		Source:    SourceRDAP,
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}

	var decoded UnifiedResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	if decoded.Query != "example.com" {
		t.Errorf("decoded.Query = %q", decoded.Query)
	}
	if decoded.Source != SourceRDAP {
		t.Errorf("decoded.Source = %q", decoded.Source)
	}
}
