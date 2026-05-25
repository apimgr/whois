package whois

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Domain name validation regex (RFC 1035, RFC 1123)
var (
	// Label must start and end with alphanumeric, can contain hyphens in between
	domainLabelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	
	// Full domain regex
	domainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// ValidateDomain validates a domain name according to RFC standards
func ValidateDomain(domain string) error {
	if domain == "" {
		return ValidationError{Field: "domain", Message: "domain cannot be empty"}
	}

	// Convert to lowercase for validation
	domain = strings.ToLower(domain)

	// Check overall length (max 253 characters)
	if len(domain) > 253 {
		return ValidationError{Field: "domain", Message: "domain exceeds maximum length of 253 characters"}
	}

	// Check if it matches domain pattern
	if !domainRegex.MatchString(domain) {
		return ValidationError{Field: "domain", Message: "invalid domain format"}
	}

	// Split into labels and validate each
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return ValidationError{Field: "domain", Message: "domain must have at least two labels (e.g., example.com)"}
	}

	for _, label := range labels {
		if err := validateDomainLabel(label); err != nil {
			return err
		}
	}

	return nil
}

// validateDomainLabel validates a single domain label
func validateDomainLabel(label string) error {
	if label == "" {
		return ValidationError{Field: "label", Message: "label cannot be empty"}
	}

	// Max length for a label is 63 characters
	if len(label) > 63 {
		return ValidationError{Field: "label", Message: fmt.Sprintf("label '%s' exceeds maximum length of 63 characters", label)}
	}

	// Check if label matches pattern
	if !domainLabelRegex.MatchString(label) {
		return ValidationError{Field: "label", Message: fmt.Sprintf("invalid label format: '%s'", label)}
	}

	return nil
}

// ValidateIPv4 validates an IPv4 address
func ValidateIPv4(ipStr string) error {
	if ipStr == "" {
		return ValidationError{Field: "ipv4", Message: "IPv4 address cannot be empty"}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ValidationError{Field: "ipv4", Message: "invalid IP address format"}
	}

	// Check if it's actually IPv4
	if ip.To4() == nil {
		return ValidationError{Field: "ipv4", Message: "not a valid IPv4 address"}
	}

	return nil
}

// ValidateIPv6 validates an IPv6 address
func ValidateIPv6(ipStr string) error {
	if ipStr == "" {
		return ValidationError{Field: "ipv6", Message: "IPv6 address cannot be empty"}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ValidationError{Field: "ipv6", Message: "invalid IP address format"}
	}

	// Check if it's actually IPv6
	if ip.To4() != nil {
		return ValidationError{Field: "ipv6", Message: "not a valid IPv6 address"}
	}

	return nil
}

// ValidateASN validates an Autonomous System Number
func ValidateASN(asnStr string) error {
	if asnStr == "" {
		return ValidationError{Field: "asn", Message: "ASN cannot be empty"}
	}

	// Remove AS prefix if present
	asnStr = strings.TrimPrefix(strings.ToUpper(asnStr), "AS")

	// Parse as number
	asn, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil {
		return ValidationError{Field: "asn", Message: "ASN must be a valid number"}
	}

	// ASN must be greater than 0
	if asn == 0 {
		return ValidationError{Field: "asn", Message: "ASN must be greater than 0"}
	}

	// ASN must be in valid range (0-4294967295 for 32-bit ASN)
	// Practical limit is 4294967295 (2^32 - 1)
	if asn > 4294967295 {
		return ValidationError{Field: "asn", Message: "ASN exceeds maximum value"}
	}

	return nil
}

// ValidateQuery validates a query based on its detected type
func ValidateQuery(query string) error {
	qtype := DetectQueryType(query)

	switch qtype {
	case QueryTypeDomain:
		return ValidateDomain(query)
	case QueryTypeIPv4:
		return ValidateIPv4(query)
	case QueryTypeIPv6:
		return ValidateIPv6(query)
	case QueryTypeASN:
		return ValidateASN(query)
	case QueryTypeUnknown:
		return ValidationError{Field: "query", Message: "unable to determine query type"}
	default:
		return ValidationError{Field: "query", Message: "unknown query type"}
	}
}
