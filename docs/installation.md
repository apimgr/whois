# Installation

## Quick Start

### Docker (Recommended)

```bash
docker run -d \
  --name caswhois \
  -p 64580:64580 \
  -v ./config:/config \
  -v ./data:/data \
  ghcr.io/casapps/caswhois:latest
```

### Binary Installation

Download the latest release for your platform:

```bash
# Linux (amd64)
wget https://github.com/casapps/caswhois/releases/latest/download/caswhois-linux-amd64
chmod +x caswhois-linux-amd64
sudo mv caswhois-linux-amd64 /usr/local/bin/caswhois

# macOS (arm64)
wget https://github.com/casapps/caswhois/releases/latest/download/caswhois-darwin-arm64
chmod +x caswhois-darwin-arm64
sudo mv caswhois-darwin-arm64 /usr/local/bin/caswhois

# Windows (amd64)
# Download caswhois-windows-amd64.exe from releases page
```

## System Requirements

- **RAM**: 512 MB minimum, 1 GB recommended
- **Disk**: 100 MB minimum
- **OS**: Linux, macOS, Windows, or FreeBSD
- **Architecture**: amd64 or arm64

## Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | amd64, arm64 | ✅ Fully Supported |
| macOS | amd64, arm64 | ✅ Fully Supported |
| Windows | amd64, arm64 | ✅ Fully Supported |
| FreeBSD | amd64, arm64 | ✅ Fully Supported |

## First Run

On first run, the server generates a setup token:

```bash
# Start the server
./caswhois

# Output will show:
# Setup Token: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
# Setup URL: http://localhost:64580/admin/server/setup
```

Navigate to the setup URL and use the token to create your admin account.

## Service Installation

### Linux (systemd)

```bash
sudo caswhois --service install
sudo systemctl enable caswhois
sudo systemctl start caswhois
```

### macOS (launchd)

```bash
sudo caswhois --service install
sudo launchctl load /Library/LaunchDaemons/org.casapps.caswhois.plist
```

### Windows (Windows Service)

```powershell
# Run as Administrator
caswhois.exe --service install
Start-Service caswhois
```

## Docker Compose

### Standard Image (Alpine-based)

```yaml
version: '3.8'

services:
  caswhois:
    image: ghcr.io/casapps/caswhois:latest
    container_name: caswhois
    ports:
      - "64580:64580"
    volumes:
      - ./config:/config
      - ./data:/data
    restart: unless-stopped
```

### All-in-One Image (with PostgreSQL, Valkey, Tor)

```yaml
version: '3.8'

services:
  caswhois:
    image: ghcr.io/casapps/caswhois:latest-aio
    container_name: caswhois-aio
    ports:
      - "64580:64580"
    volumes:
      - ./config:/config
      - ./data:/data
    restart: unless-stopped
```

## Building from Source

**Never build locally - always use Docker:**

```bash
# Clone repository
git clone https://github.com/casapps/caswhois.git
cd caswhois

# Build using Docker (via Makefile)
make build

# Output: binaries/caswhois-{os}-{arch}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CASWHOIS_CONFIG` | Config directory | `/etc/casapps/caswhois` |
| `CASWHOIS_DATA` | Data directory | `/var/lib/casapps/caswhois` |
| `CASWHOIS_PORT` | Listen port | `64580` |
| `CASWHOIS_ADDRESS` | Listen address | `0.0.0.0` |
| `CASWHOIS_MODE` | Application mode | `production` |

## Verifying Installation

```bash
# Check version
caswhois --version

# Check status
caswhois --status

# Test health endpoint
curl http://localhost:64580/healthz
```

## Upgrading

```bash
# Backup first
caswhois --maintenance backup

# Download new version
wget https://github.com/casapps/caswhois/releases/latest/download/caswhois-linux-amd64

# Replace binary
sudo systemctl stop caswhois
sudo mv caswhois-linux-amd64 /usr/local/bin/caswhois
sudo chmod +x /usr/local/bin/caswhois
sudo systemctl start caswhois
```

## Troubleshooting

### Port Already in Use

Change the port in config or use `--port`:

```bash
caswhois --port 8080
```

### Permission Denied

On Linux/macOS, use sudo for privileged operations:

```bash
sudo caswhois --service install
```

### Setup Token Not Showing

Check logs:

```bash
# Linux
journalctl -u caswhois -f

# Docker
docker logs caswhois
```

## Next Steps

- [Configuration](configuration.md) - Configure your server
- [Admin Guide](admin.md) - Manage your instance
- [API Documentation](api.md) - Integrate with the API
