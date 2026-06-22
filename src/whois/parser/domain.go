package parser

import (
	"regexp"
	"strings"
	"time"
)

// DomainResult represents parsed domain WHOIS data
type DomainResult struct {
	Domain       string    `json:"domain"`
	Registrar    string    `json:"registrar"`
	RegistrarID  string    `json:"registrar_id"`
	Registrant   string    `json:"registrant"`
	Organization string    `json:"organization"`
	Email        string    `json:"email"`
	Country      string    `json:"country,omitempty"`
	Nameservers  []string  `json:"nameservers"`
	Status       []string  `json:"status"`
	CreatedDate  time.Time `json:"created_date,omitempty"`
	UpdatedDate  time.Time `json:"updated_date,omitempty"`
	ExpiryDate   time.Time `json:"expiry_date,omitempty"`
	DNSSEC       string    `json:"dnssec"`
	Raw          string    `json:"raw"`
}

// Common WHOIS field patterns
var domainPatterns = map[string]*regexp.Regexp{
	"domain":              regexp.MustCompile(`(?i)^\s*(?:domain\s*name|domain):\s*(.+)$`),
	"registrar":           regexp.MustCompile(`(?i)^\s*registrar:\s*(.+)$`),
	"registrar_iana":      regexp.MustCompile(`(?i)^\s*registrar\s*iana\s*id:\s*(.+)$`),
	"registrant_name":     regexp.MustCompile(`(?i)^\s*registrant\s*(?:name)?:\s*(.+)$`),
	"registrant_org":      regexp.MustCompile(`(?i)^\s*registrant\s*organi[sz]ation:\s*(.+)$`),
	"registrant_email":    regexp.MustCompile(`(?i)^\s*registrant\s*email:\s*(.+)$`),
	"registrant_country":  regexp.MustCompile(`(?i)^\s*registrant\s*country:\s*(.+)$`),
	"nameserver":          regexp.MustCompile(`(?i)^\s*(?:name\s*server|nserver):\s*(.+)$`),
	"status":              regexp.MustCompile(`(?i)^\s*(?:domain\s*)?status:\s*(.+)$`),
	"created":             regexp.MustCompile(`(?i)^\s*(?:creation\s*date|created|registered\s*on):\s*(.+)$`),
	"updated":             regexp.MustCompile(`(?i)^\s*(?:updated\s*date|last\s*updated|modified):\s*(.+)$`),
	"expires":             regexp.MustCompile(`(?i)^\s*(?:expir(?:y|ation)\s*date|expires|registry\s*expiry\s*date):\s*(.+)$`),
	"dnssec":              regexp.MustCompile(`(?i)^\s*dnssec:\s*(.+)$`),
}

// ParseDomain parses raw WHOIS response for domain queries
func ParseDomain(raw string) (*DomainResult, error) {
	result := &DomainResult{
		Raw:         raw,
		Nameservers: make([]string, 0),
		Status:      make([]string, 0),
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Domain name
		if result.Domain == "" {
			if match := domainPatterns["domain"].FindStringSubmatch(line); match != nil {
				result.Domain = strings.TrimSpace(match[1])
			}
		}

		// Registrar
		if result.Registrar == "" {
			if match := domainPatterns["registrar"].FindStringSubmatch(line); match != nil {
				result.Registrar = strings.TrimSpace(match[1])
			}
		}

		// Registrar IANA ID
		if result.RegistrarID == "" {
			if match := domainPatterns["registrar_iana"].FindStringSubmatch(line); match != nil {
				result.RegistrarID = strings.TrimSpace(match[1])
			}
		}

		// Registrant name
		if result.Registrant == "" {
			if match := domainPatterns["registrant_name"].FindStringSubmatch(line); match != nil {
				result.Registrant = strings.TrimSpace(match[1])
			}
		}

		// Registrant organization
		if result.Organization == "" {
			if match := domainPatterns["registrant_org"].FindStringSubmatch(line); match != nil {
				result.Organization = strings.TrimSpace(match[1])
			}
		}

		// Registrant email
		if result.Email == "" {
			if match := domainPatterns["registrant_email"].FindStringSubmatch(line); match != nil {
				result.Email = strings.TrimSpace(match[1])
			}
		}

		// Registrant country
		if result.Country == "" {
			if match := domainPatterns["registrant_country"].FindStringSubmatch(line); match != nil {
				result.Country = strings.ToUpper(strings.TrimSpace(match[1]))
			}
		}

		// Nameservers
		if match := domainPatterns["nameserver"].FindStringSubmatch(line); match != nil {
			ns := strings.TrimSpace(match[1])
			ns = strings.ToLower(ns)
			if !contains(result.Nameservers, ns) {
				result.Nameservers = append(result.Nameservers, ns)
			}
		}

		// Status
		if match := domainPatterns["status"].FindStringSubmatch(line); match != nil {
			status := strings.TrimSpace(match[1])
			status = strings.Split(status, " ")[0]
			if !contains(result.Status, status) {
				result.Status = append(result.Status, status)
			}
		}

		// Created date
		if result.CreatedDate.IsZero() {
			if match := domainPatterns["created"].FindStringSubmatch(line); match != nil {
				if t := parseDate(match[1]); !t.IsZero() {
					result.CreatedDate = t
				}
			}
		}

		// Updated date
		if result.UpdatedDate.IsZero() {
			if match := domainPatterns["updated"].FindStringSubmatch(line); match != nil {
				if t := parseDate(match[1]); !t.IsZero() {
					result.UpdatedDate = t
				}
			}
		}

		// Expiry date
		if result.ExpiryDate.IsZero() {
			if match := domainPatterns["expires"].FindStringSubmatch(line); match != nil {
				if t := parseDate(match[1]); !t.IsZero() {
					result.ExpiryDate = t
				}
			}
		}

		// DNSSEC
		if result.DNSSEC == "" {
			if match := domainPatterns["dnssec"].FindStringSubmatch(line); match != nil {
				result.DNSSEC = strings.TrimSpace(match[1])
			}
		}
	}

	return result, nil
}

// parseDate attempts to parse various date formats
func parseDate(dateStr string) time.Time {
	dateStr = strings.TrimSpace(dateStr)

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02/01/2006",
		"01/02/2006",
		"2006.01.02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

// contains checks if string slice contains value
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
