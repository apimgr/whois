# caswhois

**WHOIS lookup service — query domains, IP addresses, and ASNs. File-only configuration, no admin web UI, token auth.**

## Features

- ✅ Server-side WHOIS queries (domain, IP, ASN)
- ✅ Built-in scheduler (no external cron needed)
- ✅ GeoIP integration (MaxMind GeoLite2)
- ✅ Prometheus metrics at the configured metrics endpoint
- ✅ Backup and restore with configurable encryption
- ✅ Self-updating via GitHub releases
- ✅ Service management (systemd, launchd, OpenRC, runit, s6, Windows SCM)
- ✅ Optional Tor v3 hidden service
- ✅ Optional I2P eepsite via i2pd or an external SAM bridge
- ✅ First-run configuration and generated operator credentials

## Browser interface

The home page (`/`) and lookup form (`/whois`) are server rendered. Public
information pages include `/about`, `/docs`, `/server/privacy`,
`/server/contact`, `/server/help`, `/server/terms`, `/server/dpo`, and
`/server/security`. The noindex `/server/contact` form is reached from the
security page and supports abuse, DMCA, privacy, and security reports. The
application also serves `/server/docs/swagger` and
`/server/docs/graphql`, and provides owner-token management and language,
theme, consent, and privacy preferences under `/server/preferences`. It has no
account login or admin settings panel; operator settings remain in `server.yml`
and `yaml.d/`, with credentials in `secrets.yml`.

## Quick Start

```bash
# Download latest release
wget https://github.com/apimgr/whois/releases/latest/download/caswhois-linux-amd64

# Make executable
chmod +x caswhois-linux-amd64

# Run server
./caswhois-linux-amd64
```

Use the listener address and port printed at startup to access the web interface.

## Documentation

- [Installation](installation.md)
- [Configuration](configuration.md)
- [CLI Reference](cli.md)
- [API Reference](api.md)
- [Security](security.md)
- [Integrations](integrations.md)
- [Development](development.md)
- [Translating](translating.md)

## License

MIT License - see [LICENSE.md](https://github.com/apimgr/whois/blob/main/LICENSE.md) for details.
