# Configuration

caswhois reads `server.yml` from its configured config directory. On first run it creates the configuration and a separate `secrets.yml`; operator credentials and encryption secrets belong in `secrets.yml`, not in `server.yml`.

## Configuration precedence

Built-in defaults are overridden by `server.yml`, environment variables, and then command-line flags. Environment variables use the `CASWHOIS_` prefix. Boolean values accept `true`/`false`, `yes`/`no`, `1`/`0`, and `on`/`off`.

```bash
caswhois --help
caswhois --config /path/to/config --port 64580
```

Unknown configuration keys and invalid values are reported during configuration loading. Safe settings can be hot reloaded; listener, database, and other startup-only settings require a restart.

## Main settings

The generated `server.yml` includes documented defaults. Common sections include:

| Section | Purpose |
|---------|---------|
| `server` | Listener, paths, API version, branding, and operator contacts |
| `server.database` | SQLite or remote libsql connection |
| `server.cache` | In-memory cache or configured Valkey/Redis backend |
| `server.rate_limit` | Read, write, health, and global burst limits |
| `server.geoip` | GeoIP database location and enabled datasets |
| `server.metrics` | Metrics enablement, route, and access token |
| `server.backup` | Backup location, encryption, and retention |
| `server.scheduler` | Built-in scheduled tasks and timezone |
| `server.ssl` | TLS certificates and Let's Encrypt settings |
| `server.tor` | Optional Tor hidden service settings |
| `server.contact.dpo` | Optional public DPO name and email |
| `web.security` | Repository vulnerability-report URL, optional policy override, and security.txt expiry |
| `web.footer` | Shared footer customization |
| `web.announcements` | Optional scheduled site banners |

Configuration is file based. There is no admin settings panel or runtime configuration API. To configure a public privacy contact, set `server.contact.dpo.name` and `server.contact.dpo.email`; the DPO page falls back to `server.contact.general.email` and never exposes the admin address.

Use `server.contact.security.email` for the optional security-reporting email address. `web.security.report_url` defaults to the repository's private vulnerability reporting page; `web.security.policy` is an optional Markdown override. The generated `/.well-known/security.txt` also publishes the security policy URL and expiry date.

## Database

SQLite is the default local database. Remote libsql/Turso is also supported. PostgreSQL and MySQL are not supported. Schema creation and additive updates run automatically at startup.

## Secrets and backups

Keep `secrets.yml` readable only by the service operator. Never commit configuration containing secrets. Backup encryption uses the configured backup password and the encryption supported by the server; follow the prompts for encrypted restore operations.

## Paths

Default paths depend on operating system and whether the process runs as root or as a user. The `--config`, `--data`, `--cache`, `--log`, and `--backup` options can override the corresponding locations. Docker uses `/config` and `/data` inside the container.

## Reloading

The server watches configuration for supported hot-reloadable settings. Settings requiring restart are identified in the server output. Restart the service after changing listener, database, TLS, or other startup-only values.

See [CLI Reference](cli.md) for command-line options and [Installation](installation.md) for service setup.
