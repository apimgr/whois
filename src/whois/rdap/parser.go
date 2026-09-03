package rdap

import (
	"encoding/json"
	"strings"
	"time"
)

// ParsedResult contains standardized fields extracted from RDAP responses
type ParsedResult struct {
	// Common fields
	Query      string `json:"query"`
	QueryType  string `json:"query_type"`
	Source     string `json:"source"`
	RDAPServer string `json:"rdap_server,omitempty"`

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
	DNSSEC      bool     `json:"dnssec,omitempty"`

	// IP-specific
	NetworkName  string `json:"network_name,omitempty"`
	NetworkRange string `json:"network_range,omitempty"`
	NetworkType  string `json:"network_type,omitempty"`

	// ASN-specific
	ASNNumber uint32 `json:"asn_number,omitempty"`
	ASNName   string `json:"asn_name,omitempty"`

	// RIR
	RIR string `json:"rir,omitempty"`

	// Raw response
	RawRDAP json.RawMessage `json:"raw_rdap,omitempty"`
}

// ParseDomainResponse extracts standardized fields from an RDAP domain response
func ParseDomainResponse(resp *DomainResponse, query, endpoint string, rawJSON []byte) *ParsedResult {
	result := &ParsedResult{
		Query:      query,
		QueryType:  "domain",
		Source:     "rdap",
		RDAPServer: endpoint,
		RawRDAP:    rawJSON,
	}

	// Domain name
	if resp.LDHName != "" {
		result.Query = strings.ToLower(resp.LDHName)
	}

	// Status
	result.Status = resp.Status

	// Nameservers
	for _, ns := range resp.Nameservers {
		if ns.LDHName != "" {
			result.Nameservers = append(result.Nameservers, strings.ToLower(ns.LDHName))
		}
	}

	// DNSSEC
	if resp.SecureDNS != nil {
		result.DNSSEC = resp.SecureDNS.DelegationSigned
	}

	// Events (dates)
	for _, event := range resp.Events {
		t := parseRDAPDate(event.EventDate)
		if t.IsZero() {
			continue
		}
		switch strings.ToLower(event.EventAction) {
		case "registration":
			result.CreatedDate = t
		case "last changed", "last update of rdap database":
			result.UpdatedDate = t
		case "expiration":
			result.ExpiryDate = t
		}
	}

	// Entities (registrant, registrar)
	for _, entity := range resp.Entities {
		parseEntity(&entity, result)
	}

	// Detect RIR from WHOIS server reference
	if resp.Port43 != "" {
		result.RIR = detectRIRFromServer(resp.Port43)
	}

	return result
}

// ParseIPResponse extracts standardized fields from an RDAP IP response
func ParseIPResponse(resp *IPResponse, query, endpoint string, rawJSON []byte, isIPv6 bool) *ParsedResult {
	queryType := "ipv4"
	if isIPv6 {
		queryType = "ipv6"
	}

	result := &ParsedResult{
		Query:      query,
		QueryType:  queryType,
		Source:     "rdap",
		RDAPServer: endpoint,
		RawRDAP:    rawJSON,
	}

	// Network info
	result.NetworkName = resp.Name
	result.NetworkType = resp.Type
	if resp.Country != "" {
		result.RegistrantCountry = strings.ToUpper(resp.Country)
	}

	// Build network range
	if resp.StartAddress != "" && resp.EndAddress != "" {
		result.NetworkRange = resp.StartAddress + " - " + resp.EndAddress
	}

	// Try CIDR notation
	if len(resp.Cidr0Cidrs) > 0 {
		cidrs := make([]string, 0)
		for _, cidr := range resp.Cidr0Cidrs {
			if cidr.V4Prefix != "" {
				cidrs = append(cidrs, cidr.V4Prefix+"/"+itoa(cidr.Length))
			}
			if cidr.V6Prefix != "" {
				cidrs = append(cidrs, cidr.V6Prefix+"/"+itoa(cidr.Length))
			}
		}
		if len(cidrs) > 0 {
			result.NetworkRange = strings.Join(cidrs, ", ")
		}
	}

	// Status
	result.Status = resp.Status

	// Events (dates)
	for _, event := range resp.Events {
		t := parseRDAPDate(event.EventDate)
		if t.IsZero() {
			continue
		}
		switch strings.ToLower(event.EventAction) {
		case "registration":
			result.CreatedDate = t
		case "last changed":
			result.UpdatedDate = t
		}
	}

	// Entities
	for _, entity := range resp.Entities {
		parseEntity(&entity, result)
	}

	// RIR detection
	if resp.Port43 != "" {
		result.RIR = detectRIRFromServer(resp.Port43)
	}
	if result.RIR == "" && endpoint != "" {
		result.RIR = detectRIRFromEndpoint(endpoint)
	}

	return result
}

// ParseASNResponse extracts standardized fields from an RDAP ASN response
func ParseASNResponse(resp *ASNResponse, asn uint32, endpoint string, rawJSON []byte) *ParsedResult {
	result := &ParsedResult{
		Query:      "AS" + itoa(int(asn)),
		QueryType:  "asn",
		Source:     "rdap",
		RDAPServer: endpoint,
		ASNNumber:  asn,
		RawRDAP:    rawJSON,
	}

	// ASN info
	result.ASNName = resp.Name
	result.NetworkType = resp.Type
	if resp.Country != "" {
		result.RegistrantCountry = strings.ToUpper(resp.Country)
	}

	// Status
	result.Status = resp.Status

	// Events
	for _, event := range resp.Events {
		t := parseRDAPDate(event.EventDate)
		if t.IsZero() {
			continue
		}
		switch strings.ToLower(event.EventAction) {
		case "registration":
			result.CreatedDate = t
		case "last changed":
			result.UpdatedDate = t
		}
	}

	// Entities
	for _, entity := range resp.Entities {
		parseEntity(&entity, result)
	}

	// RIR detection
	if resp.Port43 != "" {
		result.RIR = detectRIRFromServer(resp.Port43)
	}
	if result.RIR == "" && endpoint != "" {
		result.RIR = detectRIRFromEndpoint(endpoint)
	}

	return result
}

func parseEntity(entity *Entity, result *ParsedResult) {
	roles := make(map[string]bool)
	for _, role := range entity.Roles {
		roles[strings.ToLower(role)] = true
	}

	// Parse vCard for contact info
	name, org, email := parseVCard(entity.VCardArray)

	// Registrant
	if roles["registrant"] {
		if result.RegistrantName == "" {
			result.RegistrantName = name
		}
		if result.RegistrantOrg == "" {
			result.RegistrantOrg = org
		}
		if result.RegistrantEmail == "" {
			result.RegistrantEmail = email
		}
	}

	// Registrar
	if roles["registrar"] {
		if result.Registrar == "" {
			if name != "" {
				result.Registrar = name
			} else if org != "" {
				result.Registrar = org
			}
		}
		// Check for IANA ID in public IDs
		for _, pid := range entity.PublicIDs {
			if strings.ToLower(pid.Type) == "iana registrar id" {
				result.RegistrarID = pid.Identifier
				break
			}
		}
	}

	// Fallback: use org name if no registrant found
	if result.RegistrantOrg == "" && org != "" && !roles["registrar"] {
		result.RegistrantOrg = org
	}

	// Recursively parse nested entities
	for _, nested := range entity.Entities {
		parseEntity(&nested, result)
	}
}

// parseVCard extracts name, org, and email from a jCard (RFC 7095)
func parseVCard(vcard VCardArray) (name, org, email string) {
	if len(vcard) < 2 {
		return
	}

	// vcard[0] should be "vcard", vcard[1] is the array of properties
	props, ok := vcard[1].([]interface{})
	if !ok {
		return
	}

	for _, prop := range props {
		arr, ok := prop.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}

		propName, ok := arr[0].(string)
		if !ok {
			continue
		}

		switch strings.ToLower(propName) {
		case "fn":
			// Formatted name
			if val, ok := arr[3].(string); ok {
				name = val
			}
		case "org":
			// Organization - can be string or array
			switch v := arr[3].(type) {
			case string:
				org = v
			case []interface{}:
				if len(v) > 0 {
					if s, ok := v[0].(string); ok {
						org = s
					}
				}
			}
		case "email":
			// Email
			if val, ok := arr[3].(string); ok {
				email = val
			}
		case "adr":
			// Address - check for country (last element of address array)
			if addrArr, ok := arr[3].([]interface{}); ok && len(addrArr) >= 7 {
				if country, ok := addrArr[6].(string); ok && country != "" {
					// We could set country here, but we'd need to pass result
				}
			}
		}
	}

	return
}

func parseRDAPDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

func detectRIRFromServer(server string) string {
	server = strings.ToLower(server)
	switch {
	case strings.Contains(server, "arin"):
		return "ARIN"
	case strings.Contains(server, "ripe"):
		return "RIPE"
	case strings.Contains(server, "apnic"):
		return "APNIC"
	case strings.Contains(server, "lacnic"):
		return "LACNIC"
	case strings.Contains(server, "afrinic"):
		return "AFRINIC"
	}
	return ""
}

func detectRIRFromEndpoint(endpoint string) string {
	endpoint = strings.ToLower(endpoint)
	switch {
	case strings.Contains(endpoint, "arin"):
		return "ARIN"
	case strings.Contains(endpoint, "ripe"):
		return "RIPE"
	case strings.Contains(endpoint, "apnic"):
		return "APNIC"
	case strings.Contains(endpoint, "lacnic"):
		return "LACNIC"
	case strings.Contains(endpoint, "afrinic"):
		return "AFRINIC"
	}
	return ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	if i < 0 {
		return "-" + itoa(-i)
	}
	result := ""
	for i > 0 {
		result = string(rune('0'+i%10)) + result
		i /= 10
	}
	return result
}
