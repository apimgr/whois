# caswhois

**WHOIS lookup service with built-in scheduler, GeoIP, metrics, and comprehensive admin panel.**

## Features

- ✅ Server-side WHOIS queries (domain, IP, ASN)
- ✅ Built-in scheduler (no external cron needed)
- ✅ GeoIP integration (MaxMind)
- ✅ Prometheus metrics
- ✅ Comprehensive admin panel
- ✅ Backup & restore with encryption
- ✅ Self-updating via GitHub releases
- ✅ Service management (systemd, launchd, runit, rc.d)
- ✅ Client binary for CLI/TUI operations

## Quick Start

```bash
# Download latest release
wget https://github.com/casapps/caswhois/releases/latest/download/caswhois-linux-amd64

# Make executable
chmod +x caswhois-linux-amd64

# Run server
./caswhois-linux-amd64
```

Visit `http://localhost:64000` to access the web interface.

## Documentation

- [Installation](installation.md)
- [Configuration](configuration.md)
- [CLI Usage](cli.md)
- [API Reference](api.md)

## License

MIT License - see [LICENSE.md](../LICENSE.md) for details
