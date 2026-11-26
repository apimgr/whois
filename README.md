# caswhois

[![CI](https://github.com/apimgr/whois/actions/workflows/ci.yml/badge.svg)](https://github.com/apimgr/whois/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/apimgr/whois)](https://github.com/apimgr/whois/releases)
[![Documentation Status](https://readthedocs.org/projects/apimgr-caswhois/badge/?version=latest)](https://apimgr-caswhois.readthedocs.io/en/latest/?badge=latest)
[![License](https://img.shields.io/github/license/apimgr/whois)](LICENSE.md)

A comprehensive WHOIS lookup service that provides detailed information about domain names, IP addresses, and ASN (Autonomous System Numbers). Features both REST API endpoints and a web interface with intelligent caching and rate limiting.

---

## About

caswhois is a production-ready WHOIS service shipped as a single static binary:

- **Multi-Source Queries**: Domain names, IPv4, IPv6, and ASN lookups
- **Intelligent Caching**: Reduces upstream load with configurable TTLs
- **Persistent Dataset**: Every successful lookup is stored permanently in SQLite
- **Multiple Output Formats**: Structured JSON, plain text, and server-rendered HTML
- **File-Only Configuration**: Settings live in `server.yml` and ordered `yaml.d/` area files; credentials live in `secrets.yml` (no admin web UI)
- **Rate Limiting**: Protect against abuse while maintaining usability
- **GeoIP Integration**: Geographic information for IP addresses
- **Tor Hidden Service**: The server attempts to start a hidden service when a local Tor binary is available; failure does not prevent the web server from starting
- **I2P Eepsite**: Optional SAMv3 eepsite with a dedicated loopback listener and persistent `.b32.i2p` destination
- **Coordinated Disclosure**: Private security-report flow, PGP-encrypted storage when configured (AES-256-GCM fallback), encrypted researcher acknowledgments, one-time status links, and public disclosure credits
- **Monitoring**: Prometheus metrics built-in

**Target Users:**
- System administrators and network engineers
- Security researchers and analysts
- Domain investors and registrars
- Developers building applications that need WHOIS data

---

## Official Site

- Website: https://caswhois.apimgr.dev
- Documentation: https://apimgr-caswhois.readthedocs.io
- Source: https://github.com/apimgr/whois

---

## Features

- ✅ **Domain WHOIS**: Registration details, nameservers, ownership information
- ✅ **IP WHOIS**: Network ownership, allocation details, geographic data
- ✅ **ASN WHOIS**: Autonomous System information, routing details
- ✅ **Auto-Detection**: Automatically detects query type
- ✅ **Smart Caching**: Expiring cache reduces repeated upstream requests
- ✅ **Persistent Records**: Every successful lookup stored permanently in SQLite
- ✅ **Owner Search**: Registrant/owner reverse search over the local dataset
- ✅ **Owner Tokens**: Anonymous primary and linked token management at `/server/preferences/tokens`
- ✅ **Preferences**: Server-rendered theme, language, consent, privacy, and preference-sync pages
- ✅ **MCP**: Bearer-authenticated Model Context Protocol endpoint and connection guide
- ✅ **Rate Limiting**: Always-on per-IP read, write, health, sensitive-action, authentication-failure, and global burst limits
- ✅ **Multiple Formats**: JSON, text, and HTML output
- ✅ **Bulk Queries**: Batch lookups for server-token holders
- ✅ **File-Only Config**: Settings in `server.yml`, credentials in `secrets.yml` (no admin web UI)
- ✅ **Metrics**: Prometheus endpoint for monitoring
- ✅ **Health Checks**: Health endpoint for monitoring
- ✅ **SSL/TLS**: Let's Encrypt auto-renewal
- ✅ **Backup/Restore**: Built-in maintenance commands
- ✅ **Auto-Update**: Self-updating from releases

---

## Production Deployment

### Docker (Recommended)

**Quick Start:**
```bash
# Create a project-scoped deployment directory
mkdir -p "${TMPDIR:-/tmp}/apimgr"
DEPLOY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/apimgr/caswhois-XXXXXX")
cd "$DEPLOY_DIR"

# Download docker-compose.yml
curl -q -LSsf -O https://raw.githubusercontent.com/apimgr/whois/main/docker/docker-compose.yml

# Start the service
docker compose up -d

# Check logs
docker compose logs -f caswhois
```

Use the local URL and port printed at startup. The first-run port is selected from the configured range and can be fixed in `server.yml`.

**Production Setup:**
```bash
# Clone repository
git clone https://github.com/apimgr/whois.git
cd whois/docker

# Edit docker-compose.yml (set timezone, ports, etc.)
nano docker-compose.yml

# Start services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### Binary Installation

**Download:**
```bash
# Download latest release
curl -q -LSsf -o caswhois-linux-amd64 https://github.com/apimgr/whois/releases/latest/download/caswhois-linux-amd64

# Make executable
chmod +x caswhois-linux-amd64
sudo mv caswhois-linux-amd64 /usr/local/bin/caswhois

# Verify installation
caswhois --version
```

**Run as Service:**
```bash
# Install system service (requires root/sudo)
sudo caswhois --service --install

# Uninstall the service and delete its configured application directories
sudo caswhois --service --uninstall

# Start service
sudo systemctl start caswhois

# Enable at boot
sudo systemctl enable caswhois

# Check status
sudo systemctl status caswhois
```

**Manual Run:**
```bash
# Run in foreground
caswhois --mode production --address 127.0.0.1 --port 8080

# Run as daemon
caswhois --daemon --mode production

# Check status
caswhois --status
```

---

## Client

The companion `caswhois-cli` provides command-line WHOIS lookups and validation:

**Installation:**
```bash
# Download client
curl -q -LSsf -o caswhois-cli-linux-amd64 https://github.com/apimgr/whois/releases/latest/download/caswhois-cli-linux-amd64

# Make executable
chmod +x caswhois-cli-linux-amd64
sudo mv caswhois-cli-linux-amd64 /usr/local/bin/caswhois-cli

# First-run setup wizard
caswhois-cli
```

**Usage:**
```bash
# CLI mode (command-line)
caswhois-cli lookup example.com
caswhois-cli lookup 8.8.8.8
caswhois-cli lookup AS15169

# Validate without making an upstream lookup
caswhois-cli validate example.com
```

---

## Configuration

Configuration file: `/etc/apimgr/caswhois/server.yml` on Linux when running as root.

Operational settings live in `server.yml` and ordered `yaml.d/` area files;
credentials and the operator bearer token are stored in `secrets.yml`, while
generated application secrets are stored in the database. There is no admin web
UI; the operator edits the files and the server hot-reloads supported changes.
The generated configuration documents defaults and restart requirements. See
[Configuration](https://apimgr-caswhois.readthedocs.io/en/latest/configuration/)
for precedence, drop-ins, and reload behavior.

**Key Settings:**
```yaml
server:
  address: "0.0.0.0"
  mode: production
  rate_limit:
    read:
      requests: 120
      window: 60
    write:
      requests: 10
      window: 60
    health:
      requests: 120
      window: 60
    strict:
      requests: 10
      window: 900
    auth_failures:
      requests: 5
      window: 900
    global_burst: 240
  database:
    driver: sqlite
    dir: /var/lib/apimgr/caswhois/db
  cache:
    type: memory
    ttl: 1h
```

Caching backends: `memory` (default), `redis`, or `valkey`. Database drivers: `sqlite`
(default), `libsql`, or `turso`. PostgreSQL and MySQL are not supported.

---

## API

### REST API

The versioned API returns JSON to browsers and API clients. Non-interactive
HTTP tools such as curl receive plain text unless they send an explicit
`Accept` header; `Accept: application/json` always requests JSON. Add `.txt` to
a versioned API path or send `Accept: text/plain` for plain text. Web pages are
rendered on the server.

**Health Check:**
```bash
curl -q -LSsf -H "Accept: text/html" https://caswhois.apimgr.dev/server/healthz
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/server/healthz
```

**WHOIS Lookup (Auto-detect):**
```bash
# Domain lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/example.com

# IP lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/8.8.8.8

# ASN lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/AS15169
```

**Specific Type Lookup:**
```bash
# Force domain lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/domain/example.com

# Force IP lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/ip/8.8.8.8

# Force ASN lookup
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/asn/15169
```

**Output Formats:**
```bash
# JSON (default)
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois/example.com

# Plain text
curl -q -LSsf -H "Accept: text/plain" https://caswhois.apimgr.dev/api/v1/whois/example.com
```

**Bulk Lookup (requires authentication):**
```bash
curl -q -LSsf -X POST https://caswhois.apimgr.dev/api/v1/whois/bulk \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "queries": ["example.com", "8.8.8.8", "AS15169"]
  }'
```

**Statistics:**
```bash
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/server/stats
```

**WHOIS Servers:**
```bash
curl -q -LSsf -H "Accept: application/json" https://caswhois.apimgr.dev/api/v1/whois-servers
```

### Prometheus Metrics

Metrics endpoint (internal use only):
```bash
curl -q -LSsf https://caswhois.apimgr.dev/metrics
```

---

## Maintenance

**Backup:**
```bash
# Create a backup in the configured backup directory
caswhois --maintenance backup

# Enter an optional password when prompted to encrypt the archive
```

**Restore:**
```bash
# Restore from encrypted backup
caswhois --maintenance restore /path/to/backup.tar.gz.enc

# You'll be prompted for the password
```

**Update:**
```bash
# Check for updates
caswhois --update check

# Update to latest stable
caswhois --update yes

# Update to beta
caswhois --update branch beta
```

---

## Development

Project guides are available in the [ReadTheDocs documentation](https://apimgr-caswhois.readthedocs.io/). To contribute interface translations, follow the [translation guide](https://apimgr-caswhois.readthedocs.io/en/latest/translating/).

### Build from Source

**Prerequisites:**
- Docker (for building, no Go installation needed)
- Git

**Quick Build:**
```bash
# Clone repository
git clone https://github.com/apimgr/whois.git
cd caswhois

# Quick development build (to temp directory)
make dev

# Full release build (all 8 platforms)
make build

# Run tests
make test
```

**Development with Docker Compose:**
```bash
cd docker
docker-compose -f docker-compose.dev.yml up --build
```

**Testing:**
```bash
# Go unit tests and coverage gate
make test

# Basic compiled-binary integration tests (Docker required)
./tests/run_tests.sh

# Run the basic Docker suite directly
./tests/docker.sh

# Full init-system integration tests (run explicitly; default runs both modes)
./tests/incus.sh

# Select one init-system mode
./tests/incus.sh systemd   # Debian with systemd
./tests/incus.sh openrc    # Alpine with OpenRC

# Required package and Tor health check for a published image
./tests/docker.sh --image-check IMAGE
```

### Project Structure

```
caswhois/
├── src/                      # Go source code
│   ├── main.go              # Entry point
│   ├── server/              # HTTP server
│   ├── whois/               # WHOIS engine
│   ├── config/              # Configuration
│   ├── db/                  # Database layer
│   ├── cache/               # Cache implementation
│   └── client/              # Client binary
├── docker/                   # Docker files
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── rootfs/              # Container overlay
├── tests/                    # Test scripts
├── docs/                     # Documentation
└── Makefile                 # Build targets
```

---

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors and contributors are not responsible for any damages or losses arising from the use of this software.

WHOIS data is provided by upstream WHOIS servers. This service is a tool for querying publicly available WHOIS information. Users are responsible for complying with applicable laws and the terms of service of upstream WHOIS providers.

---

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

Third-party licenses: see [LICENSE.md](LICENSE.md)
