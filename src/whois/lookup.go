package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/whois/parser"
	"github.com/apimgr/whois/src/whois/rdap"
)

// LookupService performs WHOIS/RDAP lookups with caching
type LookupService struct {
	bootstrap  *rdap.Bootstrap
	rdapClient *rdap.Client
	cache      cache.Cache
}

// NewLookupService creates a new lookup service
func NewLookupService(dataDir string, c cache.Cache) *LookupService {
	bootstrap := rdap.NewBootstrap(dataDir)
	return &LookupService{
		bootstrap:  bootstrap,
		rdapClient: rdap.NewClient(bootstrap),
		cache:      c,
	}
}

// LoadBootstrap loads RDAP bootstrap files from disk
func (s *LookupService) LoadBootstrap() error {
	return s.bootstrap.Load()
}

// UpdateBootstrap fetches latest bootstrap files from IANA
func (s *LookupService) UpdateBootstrap(ctx context.Context) error {
	return s.bootstrap.Update(ctx)
}

// HasRDAPData returns true if RDAP bootstrap data is available
func (s *LookupService) HasRDAPData() bool {
	return s.bootstrap.HasData()
}

// Lookup performs a lookup using RDAP first, falling back to WHOIS
func (s *LookupService) Lookup(ctx context.Context, query string) (*UnifiedResult, error) {
	// Detect query type
	qtype := DetectQueryType(query)
	if qtype == QueryTypeUnknown {
		return nil, fmt.Errorf("invalid query: cannot determine type")
	}

	// Check cache if available
	if s.cache != nil {
		cacheKey := cache.WHOISKey(query)
		if data, err := s.cache.Get(ctx, cacheKey); err == nil {
			var result UnifiedResult
			if err := json.Unmarshal(data, &result); err == nil {
				result.Timestamp = time.Now()
				return &result, nil
			}
		}

		// Check failure cache
		failureKey := cache.WHOISFailureKey(query)
		if exists, _ := s.cache.Exists(ctx, failureKey); exists {
			return nil, fmt.Errorf("lookup failed recently, please try again later")
		}
	}

	// Try RDAP first if bootstrap data is available
	var result *UnifiedResult
	var err error

	if s.bootstrap.HasData() {
		result, err = s.lookupRDAP(ctx, query, qtype)
		if err == nil {
			s.cacheResult(ctx, query, qtype, result)
			return result, nil
		}
		// RDAP failed, fall through to WHOIS
	}

	// Fallback to WHOIS
	result, err = s.lookupWHOIS(ctx, query, qtype)
	if err != nil {
		// Cache failure
		if s.cache != nil {
			failureKey := cache.WHOISFailureKey(query)
			s.cache.Set(ctx, failureKey, []byte("1"), cache.DefaultTTLs.Failure)
		}
		return nil, err
	}

	s.cacheResult(ctx, query, qtype, result)
	return result, nil
}

func (s *LookupService) lookupRDAP(ctx context.Context, query string, qtype WHOISQueryType) (*UnifiedResult, error) {
	switch qtype {
	case QueryTypeDomain:
		resp, endpoint, err := s.rdapClient.QueryDomain(ctx, query)
		if err != nil {
			return nil, err
		}
		rawJSON, _ := json.Marshal(resp)
		parsed := rdap.ParseDomainResponse(resp, query, endpoint, rawJSON)
		return FromRDAPDomain(parsed), nil

	case QueryTypeIPv4:
		resp, endpoint, err := s.rdapClient.QueryIP(ctx, query, false)
		if err != nil {
			return nil, err
		}
		rawJSON, _ := json.Marshal(resp)
		parsed := rdap.ParseIPResponse(resp, query, endpoint, rawJSON, false)
		return FromRDAPIP(parsed, QueryTypeIPv4), nil

	case QueryTypeIPv6:
		resp, endpoint, err := s.rdapClient.QueryIP(ctx, query, true)
		if err != nil {
			return nil, err
		}
		rawJSON, _ := json.Marshal(resp)
		parsed := rdap.ParseIPResponse(resp, query, endpoint, rawJSON, true)
		return FromRDAPIP(parsed, QueryTypeIPv6), nil

	case QueryTypeASN:
		asn := parseASNNumber(query)
		if asn == 0 {
			return nil, fmt.Errorf("invalid ASN: %s", query)
		}
		resp, endpoint, err := s.rdapClient.QueryASN(ctx, asn)
		if err != nil {
			return nil, err
		}
		rawJSON, _ := json.Marshal(resp)
		parsed := rdap.ParseASNResponse(resp, asn, endpoint, rawJSON)
		return FromRDAPASN(parsed), nil

	default:
		return nil, fmt.Errorf("unsupported query type")
	}
}

func (s *LookupService) lookupWHOIS(ctx context.Context, query string, qtype WHOISQueryType) (*UnifiedResult, error) {
	// Select WHOIS server
	server := SelectServer(qtype, query)
	if server == "" {
		return nil, fmt.Errorf("no WHOIS server available for query type")
	}

	// Perform TCP query
	raw, err := tcpQuery(server, query)
	if err != nil {
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}

	// Parse and convert to unified result
	switch qtype {
	case QueryTypeDomain:
		parsed, err := parser.ParseDomain(raw)
		if err != nil {
			return nil, err
		}
		return FromWHOISDomain(parsed, query, server), nil

	case QueryTypeIPv4, QueryTypeIPv6:
		parsed, err := parser.ParseIP(raw)
		if err != nil {
			return nil, err
		}
		parsed.IP = query
		return FromWHOISIP(parsed, query, server, qtype), nil

	case QueryTypeASN:
		parsed, err := parser.ParseASN(raw)
		if err != nil {
			return nil, err
		}
		return FromWHOISASN(parsed, query, server), nil

	default:
		return nil, fmt.Errorf("unsupported query type")
	}
}

func (s *LookupService) cacheResult(ctx context.Context, query string, qtype WHOISQueryType, result *UnifiedResult) {
	if s.cache == nil {
		return
	}

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
		s.cache.Set(ctx, cache.WHOISKey(query), data, ttl)
	}
}

func parseASNNumber(query string) uint32 {
	query = strings.TrimSpace(query)
	query = strings.ToUpper(query)
	query = strings.TrimPrefix(query, "AS")

	n, err := strconv.ParseUint(query, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// LookupDomain performs a domain lookup (convenience method)
func (s *LookupService) LookupDomain(ctx context.Context, domain string) (*UnifiedResult, error) {
	return s.Lookup(ctx, domain)
}

// LookupIP performs an IP lookup (convenience method)
func (s *LookupService) LookupIP(ctx context.Context, ip string) (*UnifiedResult, error) {
	return s.Lookup(ctx, ip)
}

// LookupASN performs an ASN lookup (convenience method)
func (s *LookupService) LookupASN(ctx context.Context, asn string) (*UnifiedResult, error) {
	return s.Lookup(ctx, asn)
}
