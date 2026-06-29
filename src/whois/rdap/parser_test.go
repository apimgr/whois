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
