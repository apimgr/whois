package whois

import (
	"encoding/json"
	"time"

	"github.com/apimgr/whois/src/whois/parser"
	"github.com/apimgr/whois/src/whois/rdap"
)

// Source indicates which protocol provided the data
type Source string

const (
	SourceRDAP  Source = "rdap"
	SourceWHOIS Source = "whois"
)

// UnifiedResult represents a standardized lookup result from either RDAP or WHOIS
type UnifiedResult struct {
	// Query info
	Query     string         `json:"query"`
	QueryType WHOISQueryType `json:"query_type"`
	Source    Source         `json:"source"`
	Timestamp time.Time      `json:"timestamp"`

	// Server info
	WHOISServer string `json:"whois_server,omitempty"`
	RDAPServer  string `json:"rdap_server,omitempty"`

	// Registrant info
	RegistrantName    string `json:"registrant_name,omitempty"`
	RegistrantOrg     string `json:"registrant_org,omitempty"`
	RegistrantEmail   string `json:"registrant_email,omitempty"`
	RegistrantCountry string `json:"registrant_country,omitempty"`

	// Registrar info
	Registrar   string `json:"registrar,omitempty"`
	RegistrarID string `json:"registrar_id,omitempty"`

	// Dates
	CreatedDate time.Time `json:"created_date,omitempty"`
	UpdatedDate time.Time `json:"updated_date,omitempty"`
	ExpiryDate  time.Time `json:"expiry_date,omitempty"`

	// Domain-specific
	Nameservers []string `json:"nameservers,omitempty"`
	Status      []string `json:"status,omitempty"`
	DNSSEC      string   `json:"dnssec,omitempty"`

	// IP-specific
	NetworkName  string `json:"network_name,omitempty"`
	NetworkRange string `json:"network_range,omitempty"`
	NetworkType  string `json:"network_type,omitempty"`

	// ASN-specific
	ASNNumber uint32 `json:"asn_number,omitempty"`
	ASNName   string `json:"asn_name,omitempty"`

	// RIR
	RIR string `json:"rir,omitempty"`

	// Raw responses
	RawWHOIS string          `json:"raw_whois,omitempty"`
	RawRDAP  json.RawMessage `json:"raw_rdap,omitempty"`
}

// FromRDAPDomain creates a UnifiedResult from an RDAP domain response
func FromRDAPDomain(parsed *rdap.ParsedResult) *UnifiedResult {
	dnssec := "unsigned"
	if parsed.DNSSEC {
		dnssec = "signedDelegation"
	}

	return &UnifiedResult{
		Query:             parsed.Query,
		QueryType:         QueryTypeDomain,
		Source:            SourceRDAP,
		Timestamp:         time.Now(),
		RDAPServer:        parsed.RDAPServer,
		RegistrantName:    parsed.RegistrantName,
		RegistrantOrg:     parsed.RegistrantOrg,
		RegistrantEmail:   parsed.RegistrantEmail,
		RegistrantCountry: parsed.RegistrantCountry,
		Registrar:         parsed.Registrar,
		RegistrarID:       parsed.RegistrarID,
		CreatedDate:       parsed.CreatedDate,
		UpdatedDate:       parsed.UpdatedDate,
		ExpiryDate:        parsed.ExpiryDate,
		Nameservers:       parsed.Nameservers,
		Status:            parsed.Status,
		DNSSEC:            dnssec,
		RIR:               parsed.RIR,
		RawRDAP:           parsed.RawRDAP,
	}
}

// FromRDAPIP creates a UnifiedResult from an RDAP IP response
func FromRDAPIP(parsed *rdap.ParsedResult, qtype WHOISQueryType) *UnifiedResult {
	return &UnifiedResult{
		Query:             parsed.Query,
		QueryType:         qtype,
		Source:            SourceRDAP,
		Timestamp:         time.Now(),
		RDAPServer:        parsed.RDAPServer,
		RegistrantName:    parsed.RegistrantName,
		RegistrantOrg:     parsed.RegistrantOrg,
		RegistrantEmail:   parsed.RegistrantEmail,
		RegistrantCountry: parsed.RegistrantCountry,
		CreatedDate:       parsed.CreatedDate,
		UpdatedDate:       parsed.UpdatedDate,
		NetworkName:       parsed.NetworkName,
		NetworkRange:      parsed.NetworkRange,
		NetworkType:       parsed.NetworkType,
		Status:            parsed.Status,
		RIR:               parsed.RIR,
		RawRDAP:           parsed.RawRDAP,
	}
}

// FromRDAPASN creates a UnifiedResult from an RDAP ASN response
func FromRDAPASN(parsed *rdap.ParsedResult) *UnifiedResult {
	return &UnifiedResult{
		Query:             parsed.Query,
		QueryType:         QueryTypeASN,
		Source:            SourceRDAP,
		Timestamp:         time.Now(),
		RDAPServer:        parsed.RDAPServer,
		RegistrantName:    parsed.RegistrantName,
		RegistrantOrg:     parsed.RegistrantOrg,
		RegistrantEmail:   parsed.RegistrantEmail,
		RegistrantCountry: parsed.RegistrantCountry,
		CreatedDate:       parsed.CreatedDate,
		UpdatedDate:       parsed.UpdatedDate,
		ASNNumber:         parsed.ASNNumber,
		ASNName:           parsed.ASNName,
		NetworkType:       parsed.NetworkType,
		Status:            parsed.Status,
		RIR:               parsed.RIR,
		RawRDAP:           parsed.RawRDAP,
	}
}

// FromWHOISDomain creates a UnifiedResult from a WHOIS domain response
func FromWHOISDomain(parsed *parser.DomainResult, query, server string) *UnifiedResult {
	return &UnifiedResult{
		Query:             query,
		QueryType:         QueryTypeDomain,
		Source:            SourceWHOIS,
		Timestamp:         time.Now(),
		WHOISServer:       server,
		RegistrantName:    parsed.Registrant,
		RegistrantOrg:     parsed.Organization,
		RegistrantEmail:   parsed.Email,
		RegistrantCountry: parsed.Country,
		Registrar:         parsed.Registrar,
		RegistrarID:       parsed.RegistrarID,
		CreatedDate:       parsed.CreatedDate,
		UpdatedDate:       parsed.UpdatedDate,
		ExpiryDate:        parsed.ExpiryDate,
		Nameservers:       parsed.Nameservers,
		Status:            parsed.Status,
		DNSSEC:            parsed.DNSSEC,
		RawWHOIS:          parsed.Raw,
	}
}

// FromWHOISIP creates a UnifiedResult from a WHOIS IP response
func FromWHOISIP(parsed *parser.IPResult, query, server string, qtype WHOISQueryType) *UnifiedResult {
	var asn uint32
	if parsed.ASN != "" {
		// Parse ASN number from "AS12345" format
		asnStr := parsed.ASN
		if len(asnStr) > 2 && (asnStr[0] == 'A' || asnStr[0] == 'a') && (asnStr[1] == 'S' || asnStr[1] == 's') {
			asnStr = asnStr[2:]
		}
		var n int
		for _, c := range asnStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		asn = uint32(n)
	}

	// Determine RIR from WHOIS server
	rir := detectRIRFromWHOISServer(server)

	return &UnifiedResult{
		Query:             query,
		QueryType:         qtype,
		Source:            SourceWHOIS,
		Timestamp:         time.Now(),
		WHOISServer:       server,
		RegistrantOrg:     parsed.Organization,
		RegistrantCountry: parsed.Country,
		CreatedDate:       parsed.AllocationDate,
		NetworkName:       parsed.Network,
		NetworkRange:      parsed.CIDR,
		ASNNumber:         asn,
		RIR:               rir,
		RawWHOIS:          parsed.Raw,
	}
}

// FromWHOISASN creates a UnifiedResult from a WHOIS ASN response
func FromWHOISASN(parsed *parser.ASNResult, query, server string) *UnifiedResult {
	var asn uint32
	if parsed.ASN != "" {
		asnStr := parsed.ASN
		if len(asnStr) > 2 && (asnStr[0] == 'A' || asnStr[0] == 'a') && (asnStr[1] == 'S' || asnStr[1] == 's') {
			asnStr = asnStr[2:]
		}
		var n int
		for _, c := range asnStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		asn = uint32(n)
	}

	rir := detectRIRFromWHOISServer(server)

	return &UnifiedResult{
		Query:             query,
		QueryType:         QueryTypeASN,
		Source:            SourceWHOIS,
		Timestamp:         time.Now(),
		WHOISServer:       server,
		RegistrantOrg:     parsed.Organization,
		RegistrantCountry: parsed.Country,
		ASNNumber:         asn,
		ASNName:           parsed.Description,
		RIR:               rir,
		RawWHOIS:          parsed.Raw,
	}
}

func detectRIRFromWHOISServer(server string) string {
	switch {
	case contains(server, "arin"):
		return "ARIN"
	case contains(server, "ripe"):
		return "RIPE"
	case contains(server, "apnic"):
		return "APNIC"
	case contains(server, "lacnic"):
		return "LACNIC"
	case contains(server, "afrinic"):
		return "AFRINIC"
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsLower(s, substr))
}

func containsLower(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
