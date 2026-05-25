# caswhois

## Project Description

A WHOIS lookup service that provides comprehensive information about domain names, IP addresses, and ASN (Autonomous System Numbers). The service offers both REST API endpoints and a web interface for querying ownership, registration details, and network information.

**Target Users:**
- System administrators and network engineers
- Security researchers and analysts
- Domain investors and registrars
- Developers building applications that need WHOIS data
- Anyone needing domain/IP ownership information

---

## Project-Specific Features

- **Domain WHOIS**: Query registration details, nameservers, and ownership for domain names
- **IP WHOIS**: Lookup network ownership, allocation details, and geographic information for IP addresses
- **ASN WHOIS**: Retrieve Autonomous System information, routing details, and organization data
- **Multi-format Output**: Support JSON, XML, and plain text responses
- **Caching**: Intelligent caching to reduce upstream WHOIS server load
- **Rate Limiting**: Built-in protection against abuse while maintaining usability

---

## Detailed Specification

### Data Models

**Domain Query Result:**
- domain: Domain name queried
- registrar: Registrar name and IANA ID
- registrant: Owner/registrant information (name, organization, email)
- nameservers: List of authoritative nameservers
- status: Domain status codes (clientTransferProhibited, etc.)
- dates: creation_date, updated_date, expiry_date
- dnssec: DNSSEC status (signed/unsigned)
- raw: Raw WHOIS response text

**IP Query Result:**
- ip: IP address queried
- network: Network range (CIDR notation)
- organization: Organization name
- asn: Associated Autonomous System Number
- country: Country code
- abuse_contact: Abuse reporting email/phone
- allocation_date: When IP block was allocated
- raw: Raw WHOIS response text

**ASN Query Result:**
- asn: Autonomous System Number
- organization: ASN holder organization
- description: Network description
- country: Registration country
- prefixes: List of announced IP prefixes
- peers: Peering information (if available)
- raw: Raw WHOIS response text

### Business Rules

- Query responses cached for 24 hours (domain), 7 days (IP/ASN)
- Rate limit: 60 queries per minute per IP (configurable)
- Invalid queries return 400 Bad Request with error message
- WHOIS server failures cached for 5 minutes to prevent retry storms
- Privacy: User IP addresses not logged in standard mode
- GDPR compliance: Minimal data retention, anonymized analytics only

### Features

**WHOIS Lookup:**
- Auto-detect query type (domain, IPv4, IPv6, ASN)
- Query upstream WHOIS servers (IANA, regional registries)
- Parse structured data from raw WHOIS responses
- Handle different WHOIS server response formats
- Fallback to alternate WHOIS servers on failure

**Caching:**
- Redis/Valkey for distributed caching (cluster mode)
- In-memory cache for single instance mode
- TTL-based expiration
- Cache hit/miss metrics

**Output Formats:**
- JSON (default): Structured data for API consumers
- XML: For legacy system integration
- Plain text: Human-readable format for CLI/web
- HTML: Formatted web interface display

### Endpoints

See AI.md PART 14 for API structure rules. All endpoints follow `/api/v1/` prefix convention.

**WHOIS Endpoints:**
- Domain lookup: Query domain WHOIS
- IP lookup: Query IP WHOIS (v4 and v6)
- ASN lookup: Query AS information
- Bulk lookup: Query multiple domains/IPs in batch (authenticated users only)

**Utility Endpoints:**
- Validate domain/IP: Check if query is valid before lookup
- Available registrars: List supported domain registrars
- WHOIS servers: List upstream WHOIS servers by TLD/registry

### Data Sources

**Upstream WHOIS Servers:**
- IANA WHOIS: whois.iana.org (TLD/ASN root)
- Regional Internet Registries (RIR):
  - ARIN (North America): whois.arin.net
  - RIPE NCC (Europe): whois.ripe.net
  - APNIC (Asia Pacific): whois.apnic.net
  - LACNIC (Latin America): whois.lacnic.net
  - AFRINIC (Africa): whois.afrinic.net
- TLD-specific WHOIS servers (per-domain basis)

**Update Frequency:**
- WHOIS data: Queried on-demand, cached per TTL rules
- Server list: Updated weekly via built-in scheduler
- No local database of all domains (queries are proxied)

### Integration

**API Authentication:**
- Public endpoints: No auth required, rate-limited
- Bulk/batch endpoints: API token required (see AI.md PART 11)
- Admin endpoints: Admin authentication (see AI.md PART 17)

**Client Binary:**
- CLI mode: `caswhois-cli domain example.com`
- TUI mode: Interactive terminal interface
- Output format selection via flags

### Optional Features

**Multi-user Support (PART 34):**
- User accounts with API token generation
- Per-user rate limits and query history
- Usage analytics dashboard

**Organizations (PART 35):**
- Team-based access to shared query history
- Organization-level API tokens
- Centralized billing/quota management

**Custom Domains (PART 36):**
- Users can access via their own domain
- Branded WHOIS service for resellers
