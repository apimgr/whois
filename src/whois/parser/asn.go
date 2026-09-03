package parser

import (
	"regexp"
	"strings"
)

// ASNResult represents parsed ASN WHOIS data
type ASNResult struct {
	ASN          string   `json:"asn"`
	Organization string   `json:"organization"`
	Description  string   `json:"description"`
	Country      string   `json:"country"`
	Prefixes     []string `json:"prefixes,omitempty"`
	Raw          string   `json:"raw"`
}

// ASN WHOIS field patterns
var asnPatterns = map[string]*regexp.Regexp{
	"asn":          regexp.MustCompile(`(?i)^\s*(?:aut-num|as-number|asn):\s*(?:as)?(\d+)$`),
	"as_name":      regexp.MustCompile(`(?i)^\s*as-name:\s*(.+)$`),
	"organization": regexp.MustCompile(`(?i)^\s*(?:org(?:anization)?|as-orgname|owner):\s*(.+)$`),
	"description":  regexp.MustCompile(`(?i)^\s*(?:descr|as-descr):\s*(.+)$`),
	"country":      regexp.MustCompile(`(?i)^\s*country:\s*([a-z]{2})$`),
	"route":        regexp.MustCompile(`(?i)^\s*route:\s*(.+)$`),
	"route6":       regexp.MustCompile(`(?i)^\s*route6:\s*(.+)$`),
}

// ParseASN parses raw WHOIS response for ASN queries
func ParseASN(raw string) (*ASNResult, error) {
	result := &ASNResult{
		Raw:      raw,
		Prefixes: make([]string, 0),
	}

	lines := strings.Split(raw, "\n")
	descriptions := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// ASN
		if result.ASN == "" {
			if match := asnPatterns["asn"].FindStringSubmatch(line); match != nil {
				result.ASN = "AS" + strings.TrimSpace(match[1])
			}
		}

		// AS Name (often the org name)
		if result.Organization == "" {
			if match := asnPatterns["as_name"].FindStringSubmatch(line); match != nil {
				result.Organization = strings.TrimSpace(match[1])
			}
		}

		// Organization (fallback if as-name not found)
		if result.Organization == "" || isGenericOrg(result.Organization) {
			if match := asnPatterns["organization"].FindStringSubmatch(line); match != nil {
				org := strings.TrimSpace(match[1])
				if !isGenericOrg(org) {
					result.Organization = org
				}
			}
		}

		// Description (collect all)
		if match := asnPatterns["description"].FindStringSubmatch(line); match != nil {
			desc := strings.TrimSpace(match[1])
			if desc != "" && !contains(descriptions, desc) {
				descriptions = append(descriptions, desc)
			}
		}

		// Country
		if result.Country == "" {
			if match := asnPatterns["country"].FindStringSubmatch(line); match != nil {
				result.Country = strings.ToUpper(strings.TrimSpace(match[1]))
			}
		}

		// Routes (IPv4)
		if match := asnPatterns["route"].FindStringSubmatch(line); match != nil {
			route := strings.TrimSpace(match[1])
			if !contains(result.Prefixes, route) {
				result.Prefixes = append(result.Prefixes, route)
			}
		}

		// Routes (IPv6)
		if match := asnPatterns["route6"].FindStringSubmatch(line); match != nil {
			route := strings.TrimSpace(match[1])
			if !contains(result.Prefixes, route) {
				result.Prefixes = append(result.Prefixes, route)
			}
		}
	}

	// Join descriptions
	if len(descriptions) > 0 {
		result.Description = strings.Join(descriptions, " / ")
	}

	return result, nil
}
