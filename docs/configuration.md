# Configuration

caswhois reads `server.yml` from its configured config directory. On first run
it creates `server.yml` and `secrets.yml`. The operator token and encryption
key are stored in `secrets.yml`; generated application secrets are stored in
the database's `app_secrets` table.

## Configuration precedence

Command-line flags override environment variables, which override file values
and built-in defaults for settings that support them. The server currently
reads `MODE`, `DEBUG`, `PORT`, `LISTEN`, `CONFIG_DIR`, `DATA_DIR`, `LOG_DIR`,
`BACKUP_DIR`, `DATABASE_DIR`, `DATABASE_URL`, `DATABASE_DRIVER`, and the
`SMTP_*` mail settings, among other platform-specific variables. It does not
apply a general `CASWHOIS_` prefix to every configuration field. Boolean values include `true`/`false`,
`yes`/`no`, `1`/`0`, and `on`/`off` where boolean parsing is used.

```bash
caswhois --help
caswhois --config /path/to/config --port 64580
```

Configuration values are validated during loading. Unknown YAML keys are
errors and prevent an invalid configuration from being applied. Safe settings
can be hot reloaded; listener, database, and other startup-only settings
require a restart.

## Main settings

The generated `server.yml` includes documented defaults. Common sections include:

| Section | Purpose |
|---------|---------|
| `server` | Listener, paths, API version, branding, and operator contacts |
| `server.database` | SQLite or remote libsql connection |
| `server.cache` | In-memory cache or configured Valkey/Redis backend |
| `server.rate_limit` | Always-on read, write, health, strict-action, failed-authentication, and global burst limits; only the thresholds are configurable |
| `server.geoip` | GeoIP database location and enabled datasets |
| `server.metrics` | Metrics enablement, route, and access token |
| `server.backup` | Backup location, encryption, and retention |
| `server.scheduler` | Built-in scheduled tasks and timezone |
| `server.ssl` | TLS certificates and Let's Encrypt settings |
| `server.tor` | Tor hidden service and outbound-network settings |
| `server.i2p` | Optional SAMv3 eepsite, listener, and address publication settings |
| `server.contact.dpo` | Optional public DPO name and email |
| `web.security` | Repository vulnerability-report URL, optional policy override, and security.txt expiry |
| `web.footer` | Shared footer customization |
| `web.announcements` | Optional scheduled site banners |

Rate limiting is always on. `read`, `write`, and `health` define their own
request counts and window lengths; `strict` applies to sensitive owner-token
actions; `auth_failures` sets the invalid-credential lockout; `global_burst`
caps total requests per client IP. Rolling-window events are stored in
`server.db` by default, or the configured Redis/Valkey cache when one is
selected. If the active store is unavailable, the server logs one warning and
uses in-process counters until restart. There is no enable/disable switch.
When Prometheus metrics are enabled, `ratelimit_requests_total` and
`ratelimit_blocked_total` report decisions using bounded limit-class labels;
client IPs, owner IDs, and token values are never metric labels.

Configuration is file based. There is no admin settings panel or runtime configuration API. To configure a public privacy contact, set `server.contact.dpo.name` and `server.contact.dpo.email`; the DPO page falls back to `server.contact.general.email` and never exposes the admin address.

I2P is enabled with `server.i2p.enabled`, `I2P_ENABLED`, or `--i2p` (use `--i2p=false` to opt out). It defaults off on hosts and on in application containers. The server prefers its own dedicated `i2pd` process, then falls back to the SAM bridge at `127.0.0.1:7656`. The persistent destination key is stored under `{data_dir}/i2p/site/`; the generated `.b32.i2p` hostname remains stable across restarts. Set `server.i2p.expose: true` to include that address in autodiscovery and the public help/footer.

Use `server.contact.security.email` for the optional security-reporting email address. `web.security.report_url` defaults to the repository's private vulnerability reporting page; `web.security.policy` is an optional Markdown override. The generated `/.well-known/security.txt` also publishes the security policy URL and expiry date.

## Database

SQLite is the default local database. Remote libsql/Turso is also supported. PostgreSQL and MySQL are not supported. Schema creation and additive updates run automatically at startup.

## Secrets and backups

Keep `secrets.yml` and `server.yml` readable only by the service operator.
Never commit configuration containing secrets. Manual backups prompt for an
optional password; restore prompts when the selected archive is encrypted.
`CASWHOIS_BACKUP_PASSWORD` can provide the backup or restore password for
non-interactive operation.

## Paths

Default paths depend on operating system and whether the process runs as root or as a user. The `--config`, `--data`, `--cache`, `--log`, and `--backup` options can override the corresponding locations. Docker uses `/config` and `/data` inside the container.

## Reloading

The server watches configuration for supported hot-reloadable settings. Settings requiring restart are identified in the server output. Restart the service after changing listener, database, TLS, or other startup-only values.

See [CLI Reference](cli.md) for command-line options and [Installation](installation.md) for service setup.
