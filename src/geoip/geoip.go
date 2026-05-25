package geoip

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPManager handles GeoIP database operations
type GeoIPManager struct {
	mu       sync.RWMutex
	dbDir    string
	enabled  bool
	asnDB    *maxminddb.Reader
	countryDB *maxminddb.Reader
	cityDB   *maxminddb.Reader
	whoisDB  *maxminddb.Reader
	lastUpdate time.Time
}

// GeoIPConfig represents GeoIP configuration from server.yml
type GeoIPConfig struct {
	Enabled   bool
	Dir       string
	Databases DatabaseConfig
}

// DatabaseConfig specifies which databases to use
type DatabaseConfig struct {
	ASN     bool
	Country bool
	City    bool
	WHOIS   bool
}

// LookupResult contains all GeoIP data for an IP
type LookupResult struct {
	IP          string          `json:"ip"`
	ASN         *ASNResult      `json:"asn,omitempty"`
	Country     *CountryResult  `json:"country,omitempty"`
	City        *CityResult     `json:"city,omitempty"`
	WHOIS       *WHOISResult    `json:"whois,omitempty"`
}

// ASNResult contains ASN information
type ASNResult struct {
	Number       int    `json:"number" maxminddb:"autonomous_system_number"`
	Organization string `json:"organization" maxminddb:"autonomous_system_organization"`
}

// CountryResult contains country information
type CountryResult struct {
	Code string `json:"code" maxminddb:"country_code"`
}

// CityResult contains city/location information
type CityResult struct {
	City       string  `json:"city,omitempty" maxminddb:"city"`
	Region     string  `json:"region,omitempty" maxminddb:"region"`
	PostalCode string  `json:"postal_code,omitempty" maxminddb:"postal_code"`
	Latitude   float64 `json:"latitude,omitempty" maxminddb:"latitude"`
	Longitude  float64 `json:"longitude,omitempty" maxminddb:"longitude"`
	Timezone   string  `json:"timezone,omitempty" maxminddb:"timezone"`
}

// WHOISResult contains WHOIS/registrant information
type WHOISResult struct {
	Registrant  string `json:"registrant,omitempty" maxminddb:"registrant_org"`
	ASN         int    `json:"asn,omitempty" maxminddb:"asn"`
	CountryCode string `json:"country_code,omitempty" maxminddb:"country_code"`
}

// NewGeoIPManager creates a new GeoIP manager
func NewGeoIPManager(cfg GeoIPConfig) (*GeoIPManager, error) {
	m := &GeoIPManager{
		dbDir:   cfg.Dir,
		enabled: cfg.Enabled,
	}

	if !cfg.Enabled {
		log.Println("[GeoIP] Disabled in configuration")
		return m, nil
	}

	// Create database directory if it doesn't exist
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create GeoIP directory: %w", err)
	}

	// Download databases if they don't exist
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := m.ensureDatabases(ctx, cfg.Databases); err != nil {
		log.Printf("[GeoIP] Warning: failed to download databases: %v", err)
		// Continue - databases may be downloaded later by scheduler
	}

	// Load existing databases
	if err := m.loadDatabases(cfg.Databases); err != nil {
		log.Printf("[GeoIP] Warning: failed to load databases: %v", err)
		// Continue - databases may not exist yet
	}

	log.Printf("[GeoIP] Initialized (dir: %s)", cfg.Dir)
	return m, nil
}

// Lookup performs a GeoIP lookup for the given IP address
func (m *GeoIPManager) Lookup(ipStr string) (*LookupResult, error) {
	if !m.enabled {
		return nil, fmt.Errorf("GeoIP is disabled")
	}

	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &LookupResult{
		IP: ipStr,
	}

	// Lookup ASN
	if m.asnDB != nil {
		var asn ASNResult
		if err := m.asnDB.Lookup(ip, &asn); err == nil {
			result.ASN = &asn
		}
	}

	// Lookup Country
	if m.countryDB != nil {
		var country CountryResult
		if err := m.countryDB.Lookup(ip, &country); err == nil {
			result.Country = &country
		}
	}

	// Lookup City
	if m.cityDB != nil {
		var city CityResult
		if err := m.cityDB.Lookup(ip, &city); err == nil {
			result.City = &city
		}
	}

	// Lookup WHOIS
	if m.whoisDB != nil {
		var whois WHOISResult
		if err := m.whoisDB.Lookup(ip, &whois); err == nil {
			result.WHOIS = &whois
		}
	}

	return result, nil
}

// loadDatabases loads MMDB files from disk
func (m *GeoIPManager) loadDatabases(cfg DatabaseConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error

	// Load ASN database
	if cfg.ASN {
		asnPath := filepath.Join(m.dbDir, "asn.mmdb")
		if _, err := os.Stat(asnPath); err == nil {
			db, err := maxminddb.Open(asnPath)
			if err != nil {
				errors = append(errors, fmt.Errorf("ASN: %w", err))
			} else {
				m.asnDB = db
				log.Println("[GeoIP] Loaded ASN database")
			}
		}
	}

	// Load Country database
	if cfg.Country {
		countryPath := filepath.Join(m.dbDir, "country.mmdb")
		if _, err := os.Stat(countryPath); err == nil {
			db, err := maxminddb.Open(countryPath)
			if err != nil {
				errors = append(errors, fmt.Errorf("Country: %w", err))
			} else {
				m.countryDB = db
				log.Println("[GeoIP] Loaded Country database")
			}
		}
	}

	// Load City database
	if cfg.City {
		cityPath := filepath.Join(m.dbDir, "city.mmdb")
		if _, err := os.Stat(cityPath); err == nil {
			db, err := maxminddb.Open(cityPath)
			if err != nil {
				errors = append(errors, fmt.Errorf("City: %w", err))
			} else {
				m.cityDB = db
				log.Println("[GeoIP] Loaded City database")
			}
		}
	}

	// Load WHOIS database
	if cfg.WHOIS {
		whoisPath := filepath.Join(m.dbDir, "whois.mmdb")
		if _, err := os.Stat(whoisPath); err == nil {
			db, err := maxminddb.Open(whoisPath)
			if err != nil {
				errors = append(errors, fmt.Errorf("WHOIS: %w", err))
			} else {
				m.whoisDB = db
				log.Println("[GeoIP] Loaded WHOIS database")
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to load some databases: %v", errors)
	}

	return nil
}

// ensureDatabases downloads databases if they don't exist
func (m *GeoIPManager) ensureDatabases(ctx context.Context, cfg DatabaseConfig) error {
	downloads := []struct {
		enabled  bool
		filename string
		url      string
	}{
		{cfg.ASN, "asn.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn.mmdb"},
		{cfg.Country, "country.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"},
		{cfg.City, "city.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-city-mmdb/dbip-city-ipv4.mmdb"},
		{cfg.WHOIS, "whois.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"},
	}

	for _, dl := range downloads {
		if !dl.enabled {
			continue
		}

		dbPath := filepath.Join(m.dbDir, dl.filename)
		if _, err := os.Stat(dbPath); err == nil {
			// Database exists, skip
			continue
		}

		log.Printf("[GeoIP] Downloading %s...", dl.filename)
		if err := downloadDatabase(ctx, dl.url, dbPath); err != nil {
			log.Printf("[GeoIP] Failed to download %s: %v", dl.filename, err)
			continue
		}
		log.Printf("[GeoIP] Downloaded %s", dl.filename)
	}

	return nil
}

// UpdateDatabases downloads the latest databases
func (m *GeoIPManager) UpdateDatabases(ctx context.Context, cfg DatabaseConfig) error {
	log.Println("[GeoIP] Updating databases...")

	downloads := []struct {
		enabled  bool
		filename string
		url      string
	}{
		{cfg.ASN, "asn.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn.mmdb"},
		{cfg.Country, "country.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"},
		{cfg.City, "city.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-city-mmdb/dbip-city-ipv4.mmdb"},
		{cfg.WHOIS, "whois.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"},
	}

	var errors []error

	for _, dl := range downloads {
		if !dl.enabled {
			continue
		}

		dbPath := filepath.Join(m.dbDir, dl.filename)
		tmpPath := dbPath + ".tmp"

		log.Printf("[GeoIP] Downloading %s...", dl.filename)
		if err := downloadDatabase(ctx, dl.url, tmpPath); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", dl.filename, err))
			continue
		}

		// Replace old database atomically
		if err := os.Rename(tmpPath, dbPath); err != nil {
			errors = append(errors, fmt.Errorf("%s rename: %w", dl.filename, err))
			os.Remove(tmpPath)
			continue
		}

		log.Printf("[GeoIP] Updated %s", dl.filename)
	}

	// Reload databases
	if err := m.loadDatabases(cfg); err != nil {
		errors = append(errors, fmt.Errorf("reload: %w", err))
	}

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.mu.Unlock()

	if len(errors) > 0 {
		return fmt.Errorf("failed to update some databases: %v", errors)
	}

	log.Println("[GeoIP] Update complete")
	return nil
}

// LastUpdate returns the last update time
func (m *GeoIPManager) LastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

// Close closes all database readers
func (m *GeoIPManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error

	if m.asnDB != nil {
		if err := m.asnDB.Close(); err != nil {
			errors = append(errors, err)
		}
		m.asnDB = nil
	}

	if m.countryDB != nil {
		if err := m.countryDB.Close(); err != nil {
			errors = append(errors, err)
		}
		m.countryDB = nil
	}

	if m.cityDB != nil {
		if err := m.cityDB.Close(); err != nil {
			errors = append(errors, err)
		}
		m.cityDB = nil
	}

	if m.whoisDB != nil {
		if err := m.whoisDB.Close(); err != nil {
			errors = append(errors, err)
		}
		m.whoisDB = nil
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to close some databases: %v", errors)
	}

	return nil
}

// Enabled returns whether GeoIP is enabled
func (m *GeoIPManager) Enabled() bool {
	return m.enabled
}
