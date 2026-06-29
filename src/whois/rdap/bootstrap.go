package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IANA bootstrap file URLs
const (
	BootstrapDNSURL  = "https://data.iana.org/rdap/dns.json"
	BootstrapIPv4URL = "https://data.iana.org/rdap/ipv4.json"
	BootstrapIPv6URL = "https://data.iana.org/rdap/ipv6.json"
	BootstrapASNURL  = "https://data.iana.org/rdap/asn.json"
)

// BootstrapFile represents an IANA RDAP bootstrap file structure
type BootstrapFile struct {
	Version     string       `json:"version"`
	Publication string       `json:"publication"`
	Description string       `json:"description,omitempty"`
	Services    [][2][]string `json:"services"`
}

// Bootstrap manages RDAP endpoint discovery via IANA bootstrap files
type Bootstrap struct {
	dataDir string
	mu      sync.RWMutex

	// Cached mappings
	dnsServices  map[string][]string
	ipv4Services []ipv4Range
	ipv6Services []ipv6Range
	asnServices  []asnRange
}

type ipv4Range struct {
	network  *net.IPNet
	services []string
}

type ipv6Range struct {
	network  *net.IPNet
	services []string
}

type asnRange struct {
	start    uint32
	end      uint32
	services []string
}

// NewBootstrap creates a new Bootstrap manager
func NewBootstrap(dataDir string) *Bootstrap {
	return &Bootstrap{
		dataDir:      dataDir,
		dnsServices:  make(map[string][]string),
		ipv4Services: make([]ipv4Range, 0),
		ipv6Services: make([]ipv6Range, 0),
		asnServices:  make([]asnRange, 0),
	}
}

// Load loads bootstrap files from disk
func (b *Bootstrap) Load() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.loadDNS(); err != nil {
		return fmt.Errorf("loading DNS bootstrap: %w", err)
	}
	if err := b.loadIPv4(); err != nil {
		return fmt.Errorf("loading IPv4 bootstrap: %w", err)
	}
	if err := b.loadIPv6(); err != nil {
		return fmt.Errorf("loading IPv6 bootstrap: %w", err)
	}
	if err := b.loadASN(); err != nil {
		return fmt.Errorf("loading ASN bootstrap: %w", err)
	}

	return nil
}

// Update fetches latest bootstrap files from IANA
func (b *Bootstrap) Update(ctx context.Context) error {
	rdapDir := filepath.Join(b.dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		return fmt.Errorf("creating rdap directory: %w", err)
	}

	files := map[string]string{
		"dns.json":  BootstrapDNSURL,
		"ipv4.json": BootstrapIPv4URL,
		"ipv6.json": BootstrapIPv6URL,
		"asn.json":  BootstrapASNURL,
	}

	client := &http.Client{Timeout: 30 * time.Second}

	for filename, url := range files {
		if err := b.downloadFile(ctx, client, url, filepath.Join(rdapDir, filename)); err != nil {
			return fmt.Errorf("downloading %s: %w", filename, err)
		}
	}

	return b.Load()
}

func (b *Bootstrap) downloadFile(ctx context.Context, client *http.Client, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Write to temp file first, then rename (atomic)
	tmpDest := dest + ".tmp"
	f, err := os.Create(tmpDest)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmpDest)
		return err
	}

	return os.Rename(tmpDest, dest)
}

func (b *Bootstrap) loadDNS() error {
	path := filepath.Join(b.dataDir, "rdap", "dns.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var bf BootstrapFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return err
	}

	b.dnsServices = make(map[string][]string)
	for _, service := range bf.Services {
		if len(service) != 2 {
			continue
		}
		tlds := service[0]
		urls := service[1]
		for _, tld := range tlds {
			tld = strings.ToLower(strings.TrimPrefix(tld, "."))
			b.dnsServices[tld] = urls
		}
	}

	return nil
}

func (b *Bootstrap) loadIPv4() error {
	path := filepath.Join(b.dataDir, "rdap", "ipv4.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var bf BootstrapFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return err
	}

	b.ipv4Services = make([]ipv4Range, 0)
	for _, service := range bf.Services {
		if len(service) != 2 {
			continue
		}
		cidrs := service[0]
		urls := service[1]
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			b.ipv4Services = append(b.ipv4Services, ipv4Range{
				network:  network,
				services: urls,
			})
		}
	}

	return nil
}

func (b *Bootstrap) loadIPv6() error {
	path := filepath.Join(b.dataDir, "rdap", "ipv6.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var bf BootstrapFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return err
	}

	b.ipv6Services = make([]ipv6Range, 0)
	for _, service := range bf.Services {
		if len(service) != 2 {
			continue
		}
		cidrs := service[0]
		urls := service[1]
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			b.ipv6Services = append(b.ipv6Services, ipv6Range{
				network:  network,
				services: urls,
			})
		}
	}

	return nil
}

func (b *Bootstrap) loadASN() error {
	path := filepath.Join(b.dataDir, "rdap", "asn.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var bf BootstrapFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return err
	}

	b.asnServices = make([]asnRange, 0)
	for _, service := range bf.Services {
		if len(service) != 2 {
			continue
		}
		ranges := service[0]
		urls := service[1]
		for _, r := range ranges {
			// Format: "12345" or "12345-67890"
			parts := strings.Split(r, "-")
			start, err := strconv.ParseUint(parts[0], 10, 32)
			if err != nil {
				continue
			}
			end := start
			if len(parts) == 2 {
				end, err = strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					continue
				}
			}
			b.asnServices = append(b.asnServices, asnRange{
				start:    uint32(start),
				end:      uint32(end),
				services: urls,
			})
		}
	}

	return nil
}

// GetDomainEndpoints returns RDAP endpoints for a domain
func (b *Bootstrap) GetDomainEndpoints(domain string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = strings.ToLower(domain)
	parts := strings.Split(domain, ".")

	// Try progressively shorter suffixes
	for i := 0; i < len(parts); i++ {
		tld := strings.Join(parts[i:], ".")
		if urls, ok := b.dnsServices[tld]; ok {
			return urls
		}
	}

	return nil
}

// GetIPv4Endpoints returns RDAP endpoints for an IPv4 address
func (b *Bootstrap) GetIPv4Endpoints(ip string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	for _, r := range b.ipv4Services {
		if r.network.Contains(parsedIP) {
			return r.services
		}
	}

	return nil
}

// GetIPv6Endpoints returns RDAP endpoints for an IPv6 address
func (b *Bootstrap) GetIPv6Endpoints(ip string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	for _, r := range b.ipv6Services {
		if r.network.Contains(parsedIP) {
			return r.services
		}
	}

	return nil
}

// GetASNEndpoints returns RDAP endpoints for an ASN
func (b *Bootstrap) GetASNEndpoints(asn uint32) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, r := range b.asnServices {
		if asn >= r.start && asn <= r.end {
			return r.services
		}
	}

	return nil
}

// HasData returns true if bootstrap data is loaded
func (b *Bootstrap) HasData() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.dnsServices) > 0 || len(b.ipv4Services) > 0 ||
		len(b.ipv6Services) > 0 || len(b.asnServices) > 0
}
