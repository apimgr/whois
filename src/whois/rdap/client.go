package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client performs RDAP queries
type Client struct {
	httpClient *http.Client
	bootstrap  *Bootstrap
}

// NewClient creates a new RDAP client
func NewClient(bootstrap *Bootstrap) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		bootstrap: bootstrap,
	}
}

// DomainResponse represents an RDAP domain response (RFC 7483)
type DomainResponse struct {
	ObjectClassName string   `json:"objectClassName"`
	LDHName         string   `json:"ldhName"`
	UnicodeName     string   `json:"unicodeName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	Status          []string `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Nameservers     []struct {
		ObjectClassName string `json:"objectClassName"`
		LDHName         string `json:"ldhName"`
	} `json:"nameservers,omitempty"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS,omitempty"`
	Links   []Link `json:"links,omitempty"`
	Remarks []struct {
		Title       string   `json:"title,omitempty"`
		Description []string `json:"description,omitempty"`
	} `json:"remarks,omitempty"`
	Port43 string `json:"port43,omitempty"`
}

// IPResponse represents an RDAP IP network response
type IPResponse struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle,omitempty"`
	StartAddress    string   `json:"startAddress,omitempty"`
	EndAddress      string   `json:"endAddress,omitempty"`
	IPVersion       string   `json:"ipVersion,omitempty"`
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type,omitempty"`
	Country         string   `json:"country,omitempty"`
	ParentHandle    string   `json:"parentHandle,omitempty"`
	Status          []string `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Port43          string   `json:"port43,omitempty"`
	Cidr0Cidrs      []struct {
		V4Prefix string `json:"v4prefix,omitempty"`
		V6Prefix string `json:"v6prefix,omitempty"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs,omitempty"`
}

// ASNResponse represents an RDAP autnum response
type ASNResponse struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle,omitempty"`
	StartAutnum     uint32   `json:"startAutnum,omitempty"`
	EndAutnum       uint32   `json:"endAutnum,omitempty"`
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type,omitempty"`
	Country         string   `json:"country,omitempty"`
	Status          []string `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Port43          string   `json:"port43,omitempty"`
}

// Entity represents an RDAP entity (registrant, registrar, etc.)
type Entity struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle,omitempty"`
	Roles           []string     `json:"roles,omitempty"`
	VCardArray      VCardArray   `json:"vcardArray,omitempty"`
	Entities        []Entity     `json:"entities,omitempty"`
	Events          []Event      `json:"events,omitempty"`
	Links           []Link       `json:"links,omitempty"`
	PublicIDs       []PublicID   `json:"publicIds,omitempty"`
}

// VCardArray is a jCard representation (RFC 7095)
type VCardArray []interface{}

// Event represents an RDAP event
type Event struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
	EventActor  string `json:"eventActor,omitempty"`
}

// Link represents an RDAP link
type Link struct {
	Value string `json:"value,omitempty"`
	Rel   string `json:"rel,omitempty"`
	Href  string `json:"href,omitempty"`
	Type  string `json:"type,omitempty"`
}

// PublicID represents a public identifier
type PublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// ErrorResponse represents an RDAP error response
type ErrorResponse struct {
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title,omitempty"`
	Description []string `json:"description,omitempty"`
}

// QueryDomain queries RDAP for domain information
func (c *Client) QueryDomain(ctx context.Context, domain string) (*DomainResponse, string, error) {
	endpoints := c.bootstrap.GetDomainEndpoints(domain)
	if len(endpoints) == 0 {
		return nil, "", fmt.Errorf("no RDAP endpoint for domain %s", domain)
	}

	// Try each endpoint until one succeeds
	var lastErr error
	for _, baseURL := range endpoints {
		resp, endpoint, err := c.queryDomainEndpoint(ctx, baseURL, domain)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, endpoint, nil
	}

	return nil, "", fmt.Errorf("all RDAP endpoints failed: %w", lastErr)
}

func (c *Client) queryDomainEndpoint(ctx context.Context, baseURL, domain string) (*DomainResponse, string, error) {
	endpoint := strings.TrimSuffix(baseURL, "/") + "/domain/" + url.PathEscape(domain)

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, endpoint, err
	}

	var resp DomainResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, endpoint, fmt.Errorf("parsing response: %w", err)
	}

	return &resp, endpoint, nil
}

// QueryIP queries RDAP for IP information
func (c *Client) QueryIP(ctx context.Context, ip string, isIPv6 bool) (*IPResponse, string, error) {
	var endpoints []string
	if isIPv6 {
		endpoints = c.bootstrap.GetIPv6Endpoints(ip)
	} else {
		endpoints = c.bootstrap.GetIPv4Endpoints(ip)
	}

	if len(endpoints) == 0 {
		return nil, "", fmt.Errorf("no RDAP endpoint for IP %s", ip)
	}

	var lastErr error
	for _, baseURL := range endpoints {
		resp, endpoint, err := c.queryIPEndpoint(ctx, baseURL, ip)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, endpoint, nil
	}

	return nil, "", fmt.Errorf("all RDAP endpoints failed: %w", lastErr)
}

func (c *Client) queryIPEndpoint(ctx context.Context, baseURL, ip string) (*IPResponse, string, error) {
	endpoint := strings.TrimSuffix(baseURL, "/") + "/ip/" + url.PathEscape(ip)

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, endpoint, err
	}

	var resp IPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, endpoint, fmt.Errorf("parsing response: %w", err)
	}

	return &resp, endpoint, nil
}

// QueryASN queries RDAP for ASN information
func (c *Client) QueryASN(ctx context.Context, asn uint32) (*ASNResponse, string, error) {
	endpoints := c.bootstrap.GetASNEndpoints(asn)
	if len(endpoints) == 0 {
		return nil, "", fmt.Errorf("no RDAP endpoint for ASN %d", asn)
	}

	var lastErr error
	for _, baseURL := range endpoints {
		resp, endpoint, err := c.queryASNEndpoint(ctx, baseURL, asn)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, endpoint, nil
	}

	return nil, "", fmt.Errorf("all RDAP endpoints failed: %w", lastErr)
}

func (c *Client) queryASNEndpoint(ctx context.Context, baseURL string, asn uint32) (*ASNResponse, string, error) {
	endpoint := strings.TrimSuffix(baseURL, "/") + "/autnum/" + fmt.Sprintf("%d", asn)

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, endpoint, err
	}

	var resp ASNResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, endpoint, fmt.Errorf("parsing response: %w", err)
	}

	return &resp, endpoint, nil
}

func (c *Client) doRequest(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "caswhois/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for auth-required responses - skip these endpoints per spec
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("endpoint requires authentication (HTTP %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error response
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.ErrorCode != 0 {
			return nil, fmt.Errorf("RDAP error %d: %s", errResp.ErrorCode, errResp.Title)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
