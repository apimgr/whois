package geoip

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPManager handles GeoIP database operations
type GeoIPManager struct {
	mu           sync.RWMutex
	dbDir        string
	enabled      bool
	databases    DatabaseConfig
	userAgent    string
	asnDB        *maxminddb.Reader
	countryDB    *maxminddb.Reader
	cityDBv4     *maxminddb.Reader
	cityDBv6     *maxminddb.Reader
	whoisEnabled bool
	lastUpdate   time.Time
}

// GeoIPConfig represents GeoIP configuration from server.yml
type GeoIPConfig struct {
	Enabled   bool
	Dir       string
	Databases DatabaseConfig
	// UserAgent is sent on database download requests; must be a real
	// build-injected identifier, never a hardcoded version (AI.md rule:
	// "never hardcode dev values — detect at runtime").
	UserAgent string
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
	IP      string         `json:"ip"`
	ASN     *ASNResult     `json:"asn,omitempty"`
	Country *CountryResult `json:"country,omitempty"`
	City    *CityResult    `json:"city,omitempty"`
	WHOIS   *WHOISResult   `json:"whois,omitempty"`
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

// CityResult contains city/location information from sapics/ip-location-db (AI.md PART 19).
type CityResult struct {
	City        string  `json:"city,omitempty" maxminddb:"city"`
	State1      string  `json:"state1,omitempty" maxminddb:"state1"`
	State2      string  `json:"state2,omitempty" maxminddb:"state2"`
	CountryCode string  `json:"country_code,omitempty" maxminddb:"country_code"`
	Postcode    string  `json:"postcode,omitempty" maxminddb:"postcode"`
	Latitude    float64 `json:"latitude,omitempty" maxminddb:"latitude"`
	Longitude   float64 `json:"longitude,omitempty" maxminddb:"longitude"`
	Timezone    string  `json:"timezone,omitempty" maxminddb:"timezone"`
}

// WHOISResult contains WHOIS/registrant-style information. Per AI.md PART 19,
// "WHOIS is not a separate download" — no whois.mmdb file exists. This is
// built by combining the ASN and Country database results at query time.
type WHOISResult struct {
	Registrant  string `json:"registrant,omitempty"`
	ASN         int    `json:"asn,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

// NewGeoIPManager creates a new GeoIP manager
func NewGeoIPManager(cfg GeoIPConfig) (*GeoIPManager, error) {
	m := &GeoIPManager{
		dbDir:        cfg.Dir,
		enabled:      cfg.Enabled,
		userAgent:    cfg.UserAgent,
		databases:    cfg.Databases,
		whoisEnabled: cfg.Databases.WHOIS,
	}

	if !cfg.Enabled {
		log.Println("[GeoIP] Disabled in configuration")
		return m, nil
	}

	// Create database directory if it doesn't exist
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create GeoIP directory: %w", err)
	}
	m.lastUpdate = geoIPLastUpdate(cfg.Dir)

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
	if m.lastUpdate.IsZero() {
		m.lastUpdate = latestDatabaseModTime(cfg.Dir, cfg.Databases)
		if !m.lastUpdate.IsZero() {
			_ = m.writeLastUpdate(m.lastUpdate)
		}
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

	// Lookup City — sapics/ip-location-db splits city data into separate
	// IPv4 and IPv6 databases; pick the reader matching the address family.
	cityDB := m.cityDBv4
	if ip.To4() == nil {
		cityDB = m.cityDBv6
	}
	if cityDB != nil {
		var city CityResult
		if err := cityDB.Lookup(ip, &city); err == nil {
			result.City = &city
		}
	}

	// WHOIS is a combined view of ASN + Country, not a separate download
	// (AI.md PART 19: "no whois.mmdb file exists").
	if m.whoisEnabled && (result.ASN != nil || result.Country != nil) {
		whois := &WHOISResult{}
		if result.ASN != nil {
			whois.Registrant = result.ASN.Organization
			whois.ASN = result.ASN.Number
		}
		if result.Country != nil {
			whois.CountryCode = result.Country.Code
		}
		result.WHOIS = whois
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
				errors = append(errors, fmt.Errorf("country: %w", err))
			} else {
				m.countryDB = db
				log.Println("[GeoIP] Loaded Country database")
			}
		}
	}

	// Load City databases (sapics/ip-location-db ships separate IPv4/IPv6 files)
	if cfg.City {
		cityV4Path := filepath.Join(m.dbDir, "dbip-city-ipv4.mmdb")
		if _, err := os.Stat(cityV4Path); err == nil {
			db, err := maxminddb.Open(cityV4Path)
			if err != nil {
				errors = append(errors, fmt.Errorf("city ipv4: %w", err))
			} else {
				m.cityDBv4 = db
				log.Println("[GeoIP] Loaded City (IPv4) database")
			}
		}

		cityV6Path := filepath.Join(m.dbDir, "dbip-city-ipv6.mmdb")
		if _, err := os.Stat(cityV6Path); err == nil {
			db, err := maxminddb.Open(cityV6Path)
			if err != nil {
				errors = append(errors, fmt.Errorf("city ipv6: %w", err))
			} else {
				m.cityDBv6 = db
				log.Println("[GeoIP] Loaded City (IPv6) database")
			}
		}
	}

	// WHOIS is not a separate database — it's a combined view of ASN +
	// Country computed at lookup time (AI.md PART 19).
	m.whoisEnabled = cfg.WHOIS

	if len(errors) > 0 {
		return fmt.Errorf("failed to load some databases: %v", errors)
	}

	return nil
}

// ensureDatabases downloads databases if they don't exist
func (m *GeoIPManager) ensureDatabases(ctx context.Context, cfg DatabaseConfig) error {
	for _, dl := range geoipDownloadList(cfg) {
		if !dl.enabled {
			continue
		}

		dbPath := filepath.Join(m.dbDir, dl.filename)
		if _, err := os.Stat(dbPath); err == nil {
			// Database exists, skip
			continue
		}

		log.Printf("[GeoIP] Downloading %s...", dl.filename)
		if err := downloadDatabase(ctx, dl.url, dbPath, m.userAgent); err != nil {
			log.Printf("[GeoIP] Failed to download %s: %v", dl.filename, err)
			continue
		}
		log.Printf("[GeoIP] Downloaded %s", dl.filename)
	}

	return nil
}

// geoipDownloadList returns the sapics/ip-location-db files to download for
// the enabled database categories (AI.md PART 19). WHOIS is intentionally
// absent — it is a combined ASN+Country view computed at lookup time, not a
// downloadable database.
func geoipDownloadList(cfg DatabaseConfig) []struct {
	enabled  bool
	filename string
	url      string
} {
	return []struct {
		enabled  bool
		filename string
		url      string
	}{
		{cfg.ASN, "asn.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn.mmdb"},
		{cfg.Country, "country.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"},
		{cfg.City, "dbip-city-ipv4.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-city-mmdb/dbip-city-ipv4.mmdb"},
		{cfg.City, "dbip-city-ipv6.mmdb", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-city-mmdb/dbip-city-ipv6.mmdb"},
	}
}

// UpdateDatabases downloads the latest databases
func (m *GeoIPManager) UpdateDatabases(ctx context.Context, cfg DatabaseConfig) error {
	log.Println("[GeoIP] Updating databases...")

	var errors []error

	for _, dl := range geoipDownloadList(cfg) {
		if !dl.enabled {
			continue
		}

		dbPath := filepath.Join(m.dbDir, dl.filename)
		tmpPath := dbPath + ".tmp"

		log.Printf("[GeoIP] Downloading %s...", dl.filename)
		if err := downloadDatabase(ctx, dl.url, tmpPath, m.userAgent); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", dl.filename, err))
			continue
		}

		// Replace old database atomically
		if err := os.Rename(tmpPath, dbPath); err != nil {
			errors = append(errors, fmt.Errorf("%s rename: %w", dl.filename, err))
			_ = os.Remove(tmpPath)
			continue
		}

		log.Printf("[GeoIP] Updated %s", dl.filename)
	}

	// Reload databases
	if err := m.loadDatabases(cfg); err != nil {
		errors = append(errors, fmt.Errorf("reload: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to update some databases: %v", errors)
	}
	updated := time.Now().UTC()
	if err := m.writeLastUpdate(updated); err != nil {
		return fmt.Errorf("record GeoIP update time: %w", err)
	}
	m.mu.Lock()
	m.lastUpdate = updated
	m.mu.Unlock()

	log.Println("[GeoIP] Update complete")
	return nil
}

// DatasetStatus reports a public-safe cached-check value for one configured
// GeoIP database. The filesystem and reader state are inspected only by the
// health registry's background refresh, never by a health request.
func (m *GeoIPManager) DatasetStatus(database string) string {
	if !m.enabled {
		return "error"
	}
	m.mu.RLock()
	loaded := false
	switch database {
	case "asn":
		loaded = !m.databases.ASN || m.asnDB != nil
	case "country":
		loaded = !m.databases.Country || m.countryDB != nil
	case "city_ipv4":
		loaded = !m.databases.City || m.cityDBv4 != nil
	case "city_ipv6":
		loaded = !m.databases.City || m.cityDBv6 != nil
	default:
		m.mu.RUnlock()
		return "error"
	}
	lastUpdate := m.lastUpdate
	m.mu.RUnlock()
	if !loaded {
		return "error"
	}
	if lastUpdate.IsZero() {
		return "degraded"
	}
	if time.Since(lastUpdate) > 21*24*time.Hour {
		return "degraded"
	}
	return "ok"
}

func geoIPLastUpdate(directory string) time.Time {
	data, err := os.ReadFile(filepath.Join(directory, ".last_updated"))
	if err != nil {
		return time.Time{}
	}
	updated, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}
	}
	return updated.UTC()
}

func latestDatabaseModTime(directory string, cfg DatabaseConfig) time.Time {
	var latest time.Time
	for _, item := range geoipDownloadList(cfg) {
		if !item.enabled {
			continue
		}
		info, err := os.Stat(filepath.Join(directory, item.filename))
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest.UTC()
}

func (m *GeoIPManager) writeLastUpdate(updated time.Time) error {
	tmp := filepath.Join(m.dbDir, ".last_updated.tmp")
	path := filepath.Join(m.dbDir, ".last_updated")
	if err := os.WriteFile(tmp, []byte(updated.UTC().Format(time.RFC3339Nano)+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
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

	if m.cityDBv4 != nil {
		if err := m.cityDBv4.Close(); err != nil {
			errors = append(errors, err)
		}
		m.cityDBv4 = nil
	}

	if m.cityDBv6 != nil {
		if err := m.cityDBv6.Close(); err != nil {
			errors = append(errors, err)
		}
		m.cityDBv6 = nil
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

// IsCountryBlocked reports whether the given IP address is blocked by the
// denyCountries / allowCountries access control lists.
//
// Logic (matching AI.md PART 19):
//   - If allowCountries is non-empty: only IPs whose country is in the list are allowed;
//     everything else is blocked.
//   - If denyCountries is non-empty: IPs whose country is in the list are blocked.
//   - If the IP cannot be looked up, it is allowed through (fail-open).
//   - An empty denyCountries and empty allowCountries means no blocking.
func (m *GeoIPManager) IsCountryBlocked(ipStr string, denyCountries, allowCountries []string) bool {
	if !m.enabled || (len(denyCountries) == 0 && len(allowCountries) == 0) {
		return false
	}
	result, err := m.Lookup(ipStr)
	if err != nil || result == nil {
		return false
	}
	countryCode := ""
	if result.Country != nil {
		countryCode = result.Country.Code
	} else if result.City != nil {
		countryCode = result.City.CountryCode
	}
	if countryCode == "" {
		return false
	}
	// Allow-list takes precedence: block if country is NOT in the allowed set.
	if len(allowCountries) > 0 {
		for _, c := range allowCountries {
			if strings.EqualFold(c, countryCode) {
				return false
			}
		}
		return true
	}
	// Deny-list: block if country IS in the denied set.
	for _, c := range denyCountries {
		if strings.EqualFold(c, countryCode) {
			return true
		}
	}
	return false
}
