# Changelog

All notable changes to caswhois are documented here.

Follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Domain, IP, ASN, and reverse-WHOIS lookups with RDAP-first retrieval,
  WHOIS fallback, normalized records, and local history.
- Versioned REST and GraphQL APIs, OpenAPI/Swagger documentation, and a
  stateless authenticated Model Context Protocol endpoint.
- Server-rendered, localized pages for help, privacy, terms, preferences,
  owner-token management, security reporting, and health status.
- Primary and linked owner-token lifecycle management, plus consent-aware
  cross-device preference synchronization.
- Coordinated security disclosure with one-shot report IDs, encrypted report
  storage, researcher status links, operator review, and acknowledgments.
- Optional Tor hidden service and I2P eepsite support with persistent service
  identities and health reporting.
- SQLite and remote libsql/Turso storage, in-memory or Valkey/Redis caching,
  buffered request counters, and scheduled maintenance tasks.
- Configurable backups and restore, generated-secret rotation, self-update,
  GeoIP controls, Prometheus metrics, and email notifications.
- `caswhois` server and `caswhois-cli` client, system service management,
  and Docker images for standard and development use.
- Installable, offline-capable PWA and eight translations: Arabic, German,
  English, Spanish, French, Italian, Japanese, and Chinese.
