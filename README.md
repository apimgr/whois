# caswhois

[![Security](https://github.com/apimgr/whois/actions/workflows/security.yml/badge.svg)](https://github.com/apimgr/whois/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/apimgr/caswhois)](https://github.com/apimgr/whois/releases)
[![License](https://img.shields.io/github/license/apimgr/caswhois)](LICENSE.md)

A comprehensive WHOIS lookup service that provides detailed information about domain names, IP addresses, and ASN (Autonomous System Numbers). Features both REST API endpoints and a web interface with intelligent caching and rate limiting.

---

## About

caswhois is a production-ready WHOIS service shipped as a single static binary:

- **Multi-Source Queries**: Domain names, IPv4, IPv6, and ASN lookups
- **Intelligent Caching**: Reduces upstream load with configurable TTLs
- **Persistent Dataset**: Every successful lookup is stored permanently in SQLite
- **Multiple Output Formats**: JSON, XML, plain text, and HTML
- **File-Only Configuration**: All settings live in `server.yml` (no admin web UI)
- **Rate Limiting**: Protect against abuse while maintaining usability
- **GeoIP Integration**: Geographic information for IP addresses
- **Tor Hidden Service**: Auto-enabled when Tor is installed
- **Monitoring**: Prometheus metrics built-in

**Target Users:**
- System administrators and network engineers
- Security researchers and analysts
- Domain investors and registrars
- Developers building applications that need WHOIS data

---

## Official Site

- Website: https://caswhois.apimgr.dev
- Documentation: https://caswhois.readthedocs.io
- Source: https://github.com/apimgr/whois

---

## Features

- ✅ **Domain WHOIS**: Registration details, nameservers, ownership information
- ✅ **IP WHOIS**: Network ownership, allocation details, geographic data
- ✅ **ASN WHOIS**: Autonomous System information, routing details
- ✅ **Auto-Detection**: Automatically detects query type
- ✅ **Smart Caching**: 24-hour domain cache, 7-day IP/ASN cache
- ✅ **Persistent Records**: Every successful lookup stored permanently in SQLite
- ✅ **Owner Search**: Registrant/owner reverse search over the local dataset
- ✅ **Rate Limiting**: Configurable per-IP read/write limits
- ✅ **Multiple Formats**: JSON, XML, text, HTML output
- ✅ **Bulk Queries**: Batch lookups for server-token holders
- ✅ **File-Only Config**: All settings in `server.yml` (no admin web UI)
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
# Create temp directory for docker-compose
mkdir -p /tmp/caswhois-deploy && cd /tmp/caswhois-deploy

# Download docker-compose.yml
curl -q -LSsf -O https://raw.githubusercontent.com/apimgr/caswhois/main/docker/docker-compose.yml

# Start the service
docker-compose up -d

# Check logs
docker-compose logs -f caswhois
```

Access the service at `http://localhost:64580`

**Production Setup:**
```bash
# Clone repository
git clone https://github.com/apimgr/whois.git
cd caswhois/docker

# Edit docker-compose.yml (set timezone, ports, etc.)
nano docker-compose.yml

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Binary Installation

**Download:**
```bash
# Download latest release
VERSION=$(curl -s https://api.github.com/repos/apimgr/caswhois/releases/latest | grep tag_name | cut -d '"' -f 4)
wget https://github.com/apimgr/whois/releases/download/${VERSION}/caswhois-linux-amd64

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

The client binary (`caswhois-cli`) provides CLI/TUI/GUI interfaces:

**Installation:**
```bash
# Download client
VERSION=$(curl -s https://api.github.com/repos/apimgr/caswhois/releases/latest | grep tag_name | cut -d '"' -f 4)
wget https://github.com/apimgr/whois/releases/download/${VERSION}/caswhois-cli-linux-amd64

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

# TUI mode (interactive terminal)
caswhois-cli --tui

# GUI mode (graphical, auto-detected)
caswhois-cli --gui
```

---

## Configuration

Configuration file: `/etc/apimgr/caswhois/server.yml`

All settings live in `server.yml`. There is no admin web UI; the operator edits the
file and the server hot-reloads safe changes (a restart is required only for listen
address or port changes).

**Key Settings:**
```yaml
server:
  address: ":64580"
  mode: production
  rate_limit:
    read: 120
    write: 10
    health: 60
    burst: 10
  database:
    driver: sqlite
    path: /var/lib/apimgr/caswhois/db/caswhois.db
  cache:
    type: memory
    ttl:
      domain: 86400
      ip: 604800
      asn: 604800
      failure: 300
```

Caching backends: `memory` (default), `redis`, or `valkey`. Database drivers: `sqlite`
(default), `libsql`, or `turso`. PostgreSQL and MySQL are not supported.

---

## API

### REST API

All endpoints support content negotiation (JSON/XML/text based on `Accept` header).

**Health Check:**
```bash
curl -q -LSsf http://localhost:64580/healthz
curl -q -LSsf http://localhost:64580/api/v1/healthz
```

**WHOIS Lookup (Auto-detect):**
```bash
# Domain lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/example.com

# IP lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/8.8.8.8

# ASN lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/AS15169
```

**Specific Type Lookup:**
```bash
# Force domain lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/domain/example.com

# Force IP lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/ip/8.8.8.8

# Force ASN lookup
curl -q -LSsf http://localhost:64580/api/v1/whois/asn/15169
```

**Output Formats:**
```bash
# JSON (default)
curl -q -LSsf http://localhost:64580/api/v1/whois/example.com

# XML
curl -q -LSsf -H "Accept: application/xml" http://localhost:64580/api/v1/whois/example.com

# Plain text
curl -q -LSsf -H "Accept: text/plain" http://localhost:64580/api/v1/whois/example.com

# Or use query parameter
curl -q -LSsf http://localhost:64580/api/v1/whois/example.com?format=xml
```

**Bulk Lookup (requires authentication):**
```bash
curl -q -LSsf -X POST http://localhost:64580/api/v1/whois/bulk \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "queries": ["example.com", "8.8.8.8", "AS15169"]
  }'
```

**Statistics:**
```bash
curl -q -LSsf http://localhost:64580/api/v1/stats
```

**WHOIS Servers:**
```bash
curl -q -LSsf http://localhost:64580/api/v1/whois-servers
```

### Prometheus Metrics

Metrics endpoint (internal use only):
```bash
curl -q -LSsf http://localhost:64580/metrics
```

---

## Maintenance

**Backup:**
```bash
# Create encrypted backup
caswhois --maintenance backup /path/to/backup.tar.gz.enc

# You'll be prompted for a password
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

# Production test build (to binaries/)
make local

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
# Run all tests
./tests/run_tests.sh

# Docker integration tests
./tests/docker.sh

# Incus integration tests (preferred)
./tests/incus.sh
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

MIT License - see [LICENSE](LICENSE) for details.

Third-party licenses: see [LICENSE.md](LICENSE.md)
