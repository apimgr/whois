package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/cache"
	"github.com/casapps/caswhois/src/whois/parser"
)

// WHOISQueryType represents the type of WHOIS query
type WHOISQueryType int

const (
	QueryTypeDomain WHOISQueryType = iota
	QueryTypeIPv4
	QueryTypeIPv6
	QueryTypeASN
	QueryTypeUnknown
)

// Query represents a WHOIS query
type Query struct {
	Type   WHOISQueryType
	Value  string
	Server string
}

// WHOISResult represents a WHOIS query result
type WHOISResult struct {
	Query     string                `json:"query"`
	Type      WHOISQueryType        `json:"type"`
	Server    string                `json:"server"`
	Raw       string                `json:"raw"`
	Timestamp time.Time             `json:"timestamp"`
	Domain    *parser.DomainResult  `json:"domain,omitempty"`
	IP        *parser.IPResult      `json:"ip,omitempty"`
	ASN       *parser.ASNResult     `json:"asn,omitempty"`
}

// DetectQueryType determines the type of query
func DetectQueryType(query string) WHOISQueryType {
	query = strings.TrimSpace(query)

	// ASN detection (AS12345 or just 12345)
	if matched, _ := regexp.MatchString(`^(AS|as)?\d+$`, query); matched {
		return QueryTypeASN
	}

	// IPv4 detection
	if ip := net.ParseIP(query); ip != nil && ip.To4() != nil {
		return QueryTypeIPv4
	}

	// IPv6 detection
	if ip := net.ParseIP(query); ip != nil && ip.To4() == nil {
		return QueryTypeIPv6
	}

	// Domain detection (basic check)
	if matched, _ := regexp.MatchString(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`, strings.ToLower(query)); matched {
		return QueryTypeDomain
	}

	return QueryTypeUnknown
}

// SelectServer determines which WHOIS server to use
func SelectServer(qtype WHOISQueryType, value string) string {
	var server Server
	
	switch qtype {
	case QueryTypeDomain:
		server = GetServerForDomain(value)
	case QueryTypeIPv4, QueryTypeIPv6:
		server = GetServerForIP(value)
	case QueryTypeASN:
		server = GetServerForASN(value)
	default:
		return ""
	}

	return server.Address()
}

// QueryWHOIS performs a WHOIS query with caching
func QueryWHOIS(query string) (*WHOISResult, error) {
	return QueryWHOISWithCache(context.Background(), query, nil)
}

// QueryWHOISWithCache performs a WHOIS query with optional caching
func QueryWHOISWithCache(ctx context.Context, query string, c cache.Cache) (*WHOISResult, error) {
	// Detect query type
	qtype := DetectQueryType(query)
	if qtype == QueryTypeUnknown {
		return nil, fmt.Errorf("invalid query: cannot determine type")
	}

	// Check cache if available
	if c != nil {
		cacheKey := cache.WHOISKey(query)
		if data, err := c.Get(ctx, cacheKey); err == nil {
			var result WHOISResult
			if err := json.Unmarshal(data, &result); err == nil {
				result.Timestamp = time.Now()
				return &result, nil
			}
		}

		failureKey := cache.WHOISFailureKey(query)
		if exists, _ := c.Exists(ctx, failureKey); exists {
			return nil, fmt.Errorf("WHOIS query failed recently, please try again later")
		}
	}

	// Select server
	server := SelectServer(qtype, query)
	if server == "" {
		return nil, fmt.Errorf("no WHOIS server available for query type")
	}

	// Perform TCP query
	raw, err := tcpQuery(server, query)
	if err != nil {
		if c != nil {
			failureKey := cache.WHOISFailureKey(query)
			c.Set(ctx, failureKey, []byte("1"), cache.DefaultTTLs.Failure)
		}
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}

	// Build result
	result := &WHOISResult{
		Query:     query,
		Type:      qtype,
		Server:    server,
		Raw:       raw,
		Timestamp: time.Now(),
	}

	// Parse response based on type
	switch qtype {
	case QueryTypeDomain:
		parsed, err := parser.ParseDomain(raw)
		if err == nil {
			result.Domain = parsed
		}
	case QueryTypeIPv4, QueryTypeIPv6:
		parsed, err := parser.ParseIP(raw)
		if err == nil {
			result.IP = parsed
			result.IP.IP = query
		}
	case QueryTypeASN:
		parsed, err := parser.ParseASN(raw)
		if err == nil {
			result.ASN = parsed
		}
	}

	// Cache successful result
	if c != nil {
		var ttl time.Duration
		switch qtype {
		case QueryTypeDomain:
			ttl = cache.DefaultTTLs.Domain
		case QueryTypeIPv4, QueryTypeIPv6:
			ttl = cache.DefaultTTLs.IP
		case QueryTypeASN:
			ttl = cache.DefaultTTLs.ASN
		default:
			ttl = 1 * time.Hour
		}

		if data, err := json.Marshal(result); err == nil {
			c.Set(ctx, cache.WHOISKey(query), data, ttl)
		}
	}

	return result, nil
}

// tcpQuery performs a raw TCP query to a WHOIS server
func tcpQuery(server, query string) (string, error) {
	// Connect to WHOIS server
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send query
	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", fmt.Errorf("write failed: %w", err)
	}

	// Read response
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("read failed: %w", err)
	}

	return string(buf[:n]), nil
}

// String returns the query type as a string
func (qt WHOISQueryType) String() string {
	switch qt {
	case QueryTypeDomain:
		return "domain"
	case QueryTypeIPv4:
		return "ipv4"
	case QueryTypeIPv6:
		return "ipv6"
	case QueryTypeASN:
		return "asn"
	default:
		return "unknown"
	}
}
