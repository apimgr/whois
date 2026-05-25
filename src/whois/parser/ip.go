package parser

import (
	"regexp"
	"strings"
	"time"
)

// IPResult represents parsed IP WHOIS data
type IPResult struct {
	IP             string    `json:"ip"`
	Network        string    `json:"network"`
	CIDR           string    `json:"cidr"`
	Organization   string    `json:"organization"`
	ASN            string    `json:"asn"`
	Country        string    `json:"country"`
	AbuseContact   string    `json:"abuse_contact"`
	AllocationDate time.Time `json:"allocation_date,omitempty"`
	Raw            string    `json:"raw"`
}

// IP WHOIS field patterns
var ipPatterns = map[string]*regexp.Regexp{
	"network":        regexp.MustCompile(`(?i)^\s*(?:inetnum|netrange|network):\s*(.+)$`),
	"cidr":           regexp.MustCompile(`(?i)^\s*cidr:\s*(.+)$`),
	"organization":   regexp.MustCompile(`(?i)^\s*(?:org(?:anization)?|orgname|owner|descr):\s*(.+)$`),
	"asn":            regexp.MustCompile(`(?i)^\s*(?:origin|originas|origin\s*as):\s*(?:as)?(\d+)$`),
	"country":        regexp.MustCompile(`(?i)^\s*country:\s*([a-z]{2})$`),
	"abuse_email":    regexp.MustCompile(`(?i)^\s*(?:abuse-(?:c|mailbox)|orgabuseemail):\s*(.+)$`),
	"abuse_phone":    regexp.MustCompile(`(?i)^\s*(?:abuse-phone|orgabusephone):\s*(.+)$`),
	"allocated":      regexp.MustCompile(`(?i)^\s*(?:allocated|created|regdate):\s*(.+)$`),
}

// ParseIP parses raw WHOIS response for IP queries
func ParseIP(raw string) (*IPResult, error) {
	result := &IPResult{
		Raw: raw,
	}

	lines := strings.Split(raw, "\n")
	var abuseEmail, abusePhone string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Network range
		if result.Network == "" {
			if match := ipPatterns["network"].FindStringSubmatch(line); match != nil {
				result.Network = strings.TrimSpace(match[1])
			}
		}

		// CIDR
		if result.CIDR == "" {
			if match := ipPatterns["cidr"].FindStringSubmatch(line); match != nil {
				result.CIDR = strings.TrimSpace(match[1])
			}
		}

		// Organization (get first non-generic description)
		if result.Organization == "" || isGenericOrg(result.Organization) {
			if match := ipPatterns["organization"].FindStringSubmatch(line); match != nil {
				org := strings.TrimSpace(match[1])
				if !isGenericOrg(org) {
					result.Organization = org
				}
			}
		}

		// ASN
		if result.ASN == "" {
			if match := ipPatterns["asn"].FindStringSubmatch(line); match != nil {
				result.ASN = "AS" + strings.TrimSpace(match[1])
			}
		}

		// Country
		if result.Country == "" {
			if match := ipPatterns["country"].FindStringSubmatch(line); match != nil {
				result.Country = strings.ToUpper(strings.TrimSpace(match[1]))
			}
		}

		// Abuse email
		if abuseEmail == "" {
			if match := ipPatterns["abuse_email"].FindStringSubmatch(line); match != nil {
				abuseEmail = strings.TrimSpace(match[1])
			}
		}

		// Abuse phone
		if abusePhone == "" {
			if match := ipPatterns["abuse_phone"].FindStringSubmatch(line); match != nil {
				abusePhone = strings.TrimSpace(match[1])
			}
		}

		// Allocation date
		if result.AllocationDate.IsZero() {
			if match := ipPatterns["allocated"].FindStringSubmatch(line); match != nil {
				if t := parseDate(match[1]); !t.IsZero() {
					result.AllocationDate = t
				}
			}
		}
	}

	// Combine abuse contact
	if abuseEmail != "" {
		result.AbuseContact = abuseEmail
		if abusePhone != "" {
			result.AbuseContact += " / " + abusePhone
		}
	} else if abusePhone != "" {
		result.AbuseContact = abusePhone
	}

	return result, nil
}

// isGenericOrg checks if organization name is too generic
func isGenericOrg(org string) bool {
	org = strings.ToLower(strings.TrimSpace(org))
	generic := []string{
		"",
		"---",
		"n/a",
		"na",
		"none",
		"reserved",
		"private",
		"network",
	}

	for _, g := range generic {
		if org == g {
			return true
		}
	}

	return false
}
