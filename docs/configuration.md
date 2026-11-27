# Configuration

caswhois reads configuration from its configured config directory. On first
run it creates node settings in `server.yml`, credentials in `secrets.yml`, and
uses built-in defaults for other settings. Area settings can be placed in
ordered YAML files in `yaml.d/` (for example `branding.yml`, `contact.yml`, and
`maintenance.yml`). Generated application secrets are stored in the database's
`app_secrets` table.

## Configuration precedence

Command-line flags override environment variables, which override merged file
values and built-in defaults for settings that support those sources. The
merged file precedence is built-in defaults, `server.yml`, `yaml.d/` files in
lexical filename order, then recognized credentials from `secrets.yml`.
Supported configuration overrides include `MODE`, `DEBUG`, `PORT`, `LISTEN`,
`CONFIG_DIR`, `DATA_DIR`, `LOG_DIR`, `BACKUP_DIR`, `DATABASE_DIR`,
`DATABASE_URL`, `DATABASE_DRIVER`, `I2P_ENABLED`, `APPLICATION_NAME`,
`APPLICATION_TAGLINE`, and SMTP variables `SMTP_HOST`, `SMTP_PORT`,
`SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, and
`SMTP_FROM_EMAIL`. `NO_COLOR` and `TERM=dumb` control console color; service
manager variables are used only for runtime detection. There is no general
`CASWHOIS_` prefix for every setting. Boolean values include `true`/`false`,
`yes`/`no`, `1`/`0`, and `on`/`off` where boolean parsing is used.

```bash
caswhois --help
caswhois --config /path/to/config --port 64580
```

Invalid values are replaced with defaults and logged with their file and key.
Malformed YAML uses the last successfully parsed version for that file (or
built-in defaults when there is no prior version). Unknown keys in modeled
sections are warned about and skipped. Safe settings can be hot reloaded;
listener, database, TLS, daemon, PID-file, and Tor settings require a restart.

`server.yml` contains this node's listener, identity, database, cache, TLS,
and trusted-proxy settings. Other non-secret settings live in named files in
`yaml.d/`; credentials live in `secrets.yml`. The server automatically backs
up and moves legacy area settings into their matching file. Existing area-file
values win when migrating duplicates.

## Main settings

The first-run `server.yml` is intentionally small; it does not contain the
whole configuration. The configuration loader merges it with `yaml.d/*.yml`
and `secrets.yml`. This is the complete supported settings index, including
nested fields; fields described as secret are accepted only in `secrets.yml`.
Defaults are supplied by the program and may be runtime-resolved from the
operating system, container mode, or available services.

### Node settings (`server.yml`)

| YAML path | Settings and purpose |
|---------|---------------------|
| `server` (`server.yml`) | `port`, `address`, `mode`, `fqdn`, `daemonize`, `pidfile`, `api_version`, `baseurl`, and `debug`. `port` may contain both HTTP and HTTPS ports; a zero/empty first-run port is selected and persisted. |
| `server.user`, `server.group`, `server.config_dir`, `server.data_dir`, `server.log_dir`, `server.cache_dir`, `server.backup.dir` (`server.yml`) | Optional service identity and directory overrides. Empty paths use the platform-specific locations; user/group apply to supported bare-host service installs. CLI and environment directory overrides take precedence. Service installation prepares these directories for the service account, and uninstall removes them. |
| `server.database` | `driver` (`sqlite`, `libsql`, or `turso`), `url`, `token` (credential), and `dir`. A URL selects the remote libsql/Turso connection; otherwise SQLite is used. |
| `server.cache` | `type` (`none`, `memory`, `valkey`, or `redis`), `url`, `host`, `port`, `username`, `password` (credential), `db`, `tls`, `tls_skip_verify`, `pool_size`, `min_idle`, `timeout`, `prefix`, `ttl`. URL takes precedence over individual connection fields. |
| `server.ssl` | `enabled`, `domain`, `email`, `challenge` (`http-01`, `tls-alpn-01`, or `dns-01`), `min_version`, `staging`, `dns_provider`, `dns_credentials` (credential map). |
| `server.trusted_proxies` | `additional`: trusted IP addresses, CIDRs, or DNS names allowed to supply forwarded client/protocol headers. |

### Application settings (`yaml.d/`)

| YAML path | Settings and purpose |
|---------|---------------------|
| `server.security` (`security.yml`) | `reports.retention_days`; `encryption_key` and `encryption_key_version` are credentials/state stored in `secrets.yml`, not in an area file. |
| `server.branding` (`branding.yml`) | `title`, `tagline`, `description`, `theme`, `accent_color`, `logo`, `favicon`; `content.header`; `content.about`, `.privacy`, `.terms`, `.footer` each accept `format` and `body`. `web.ui.theme` and `web.ui.accent` are the shared UI overrides. |
| `server.seo` (`branding.yml`) | `keywords`, `author`, `og_image`, `twitter_handle`, `title_separator`, `meta_tags`, `canonical`, `noindex`. |
| `server.pages` (`pages.yml`) | `about.content`, `privacy.content`, `terms.content`; `help.content` and `help.mcp`; `contact.enabled`, `contact.captcha`, `contact.antispam.*`, `contact.captcha_site_key`, `contact.success_message`. `captcha_secret_key` is a credential stored in `secrets.yml`. Antispam fields are `honeypot`, `min_fill_seconds`, `max_age_seconds`, `per_ip`, `per_email`, `global`, `window`, `max_links`, `reject_markup`, `blocked_words`, and `blocked_email_domains`. |
| `server.contact` (`contact.yml`) | `admin`, `security`, `abuse`, and `general` each have `email` and `webhooks`; webhook destinations are `telegram`, `discord`, `slack`, `mattermost`, `pushover`, `gotify`, and `generic`. `dpo.name` and `dpo.email` supply the public DPO page. Contact destinations and webhook URLs are private configuration. |
| `server.privacy` (`privacy.yml`) | `data.sold`, `data.stored_on_server`, `data.sharing[]` (`condition`, `when`, `data`); `retention.period`, `retention.export_available`, `retention.deletion_available`; `consent.show_until_acknowledged`, `default_enabled`, `message`, `message_if_sold`, `policy.text`, `policy.url`, `buttons.decline`, `buttons.accept`, `position`, `show_preferences`, `preferences_text`; `cookies.essential`, `.preferences`, `.analytics` each have `enabled` and `description`, and analytics also has `description_suffix_not_sold` and `description_suffix_sold`; `third_party.services[]` has `name`, `purpose`, `data_sent`, and `policy_url`; `content.data_collection`, `data_usage`, `data_usage_if_sold`, and `data_security` provide page Markdown. `server.compliance.enabled` is stored in the privacy area and requires encrypted backups. |
| `server.tracking` (`privacy.yml`) | `type` (`umami`, `simple`, `cloudflare`, or empty), `id`, and `url` configure optional site analytics. |
| `server.csrf` (`web.yml`) | `enabled`, `token_length`, `cookie_name`, `header_name`, `secure` (`auto`, `true`, or `false`), and `exempt_paths`. CSRF is enabled by default for browser forms. |
| `server.cors` (`web.yml`) | `allowed_origins`, `allow_credentials`, and `max_age`. Credentials are never combined with wildcard origins. |
| `server.compression` (`web.yml`) | `enabled`, `level` (1–9), and MIME `types` control HTTP response compression. |
| `server.healthz` (`web.yml`) | `root.enabled` controls the optional `/healthz` alias; `/server/healthz` remains available. |
| `server.i18n` (`web.yml`) | `default_language` and `supported`; supported languages must include the required locale set and the default must be enabled. |
| `web.security` (`web.yml`) | `report_url`, `expires`, and Markdown `policy` control the public vulnerability reporting links and policy. |
| `web.footer` (`web.yml`) | `custom_html`: empty uses the standard footer, whitespace disables the optional branding row, and non-empty content is sanitized before rendering. |
| `web.announcements` (`web.yml`) | `enabled` and `messages[]`; each message has `id`, `type`, `title`, `message`, `start`, `end`, and `dismissible`. Times are ISO 8601; an empty bound is unbounded. |
| `server.rate_limit` (`security.yml`) | `read`, `write`, `health`, `strict`, and `auth_failures` each have `requests` and `window` (seconds); `global_burst` sets the per-client aggregate ceiling. Limits are always active. |
| `server.tokens` (`security.yml`) | `max_linked`, `cookie_max_age`, and `idle_purge_days` set owner-token limits and lifecycle. |
| `server.geoip` (`security.yml`) | `enabled`, `dir`, `deny_countries`, `allow_countries`, and `databases.asn`, `.country`, `.city`, `.whois` configure GeoIP controls and datasets. |
| `server.limits` (`security.yml`) | `max_body_size`, `read_timeout`, `write_timeout`, and `idle_timeout` set request and connection limits. |
| `server.reverse_whois` (`app.yml`) | `provider` (`securitytrails`, `whoxy`, `viewdns`, or empty), `api_key` (credential), and `max_results`. Local records are searched before an optional provider. |
| `server.metrics` (`metrics.yml`) | `enabled`, `endpoint`, `include_system`, `include_runtime`, `token`, `duration_buckets`, and `size_buckets` configure Prometheus scraping. The token is a credential; empty means network access must be restricted externally. |
| `server.logs` (`logs.yml`) | `level`; `access`, `server`, `error`, `app`, `auth`, `audit`, `security`, and `debug` each have `enabled`, `filename`, `format`, `custom`, `rotate`, `keep`, and `compress`. `format` is log-type specific. |
| `server.notifications` (`notifications.yml`) | `webui.position`, `.duration` (success/info toast seconds), and `.warning_duration` (warning toast seconds); either duration can be `0` for manual dismissal. Error toasts never auto-dismiss. Also configures `email.smtp.host`, `.port`, `.username`, `.password`, `.tls`; `email.from.name`, `.email`; and `email.events.startup`, `shutdown`, `backup_complete`, `backup_failed`, `ssl_expiring`, `ssl_renewed`, `ssl_renewal_failed`, `security_alert`, `scheduler_error`, `update_available`, `update_installed`. SMTP credentials are private. |
| `server.scheduler` (`maintenance.yml`) | `timezone`, `catch_up_window`, `max_retries`, `retry_delay`, `backoff`, and `tasks.<task-id>`. Task overrides have `schedule`, `enabled`, `retry_on_fail`, `retry_delay`, `verify`, `retention`, and `restart_on_fail`; persisted task state may take precedence after first run. |
| `server.backup` (`maintenance.yml`) | `dir`, `encryption.enabled`, and `retention.max_backups`, `keep_weekly`, `keep_monthly`, `keep_yearly`, `max_total_size`. The size cap accepts a percentage or absolute size and overrides count limits. |
| `server.maintenance` (`maintenance.yml`) | `self_healing.retry_interval`, `.max_attempts`; `cleanup.disk_threshold`, `.log_retention_days`, `.backup_keep_count`; `notify.on_enter`, `.on_exit`. Self-healing is always enabled; a zero attempt cap means retry indefinitely. |
| `server.update` (`maintenance.yml`) | `branch` (`stable`, `beta`, or `daily`), `auto_install`, and `defer_days` (0–365). Automatic installation is off by default. |
| `server.tor` (`tor.yml`) | `binary`, `expose`, `use_network`, `allow_user_preference`, `max_circuits`, `startup_timeout`, `circuit_timeout`, `bootstrap_timeout`, `safe_logging`, `max_streams_per_circuit`, `close_circuit_on_stream_limit`, `bandwidth_rate`, `bandwidth_burst`, `max_monthly_bandwidth`, `num_intro_points`, `virtual_port`, and `contact_email`. The onion address is runtime state from Tor's `HiddenServiceDir` hostname file; it is not a setting to place in `server.yml`. |
| `server.i2p` (`i2p.yml`) | `enabled`, `expose`, `binary`, `sam_address`, `virtual_port`, `inbound_length`, `outbound_length`, `inbound_quantity`, `outbound_quantity`, `signature_type`, and `bootstrap_timeout`. I2P is opt-in outside application containers. |

### Credentials (`secrets.yml`)

The operator token is `server.token`. Database/cache/SMTP credentials,
reverse-WHOIS keys, DNS provider credentials, CAPTCHA secret, and the encryption
key are stored here when configured. The file is mode `0600`; do not include
its values in logs, screenshots, or source control. `server.yml` and the area
files must not be used to store credentials.

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
caps total requests per client IP. Hot counters are buffered in memory and
flushed to SQLite in bounded batches; Redis/Valkey is used for request rate
limiting when selected. If the active store is unavailable, the server logs
one warning and uses in-process counters until restart. There is no
enable/disable switch.
When Prometheus metrics are enabled, `ratelimit_requests_total` and
`ratelimit_blocked_total` report decisions using bounded limit-class labels;
client IPs, owner IDs, and token values are never metric labels.

Configuration is file based. There is no admin settings panel or runtime configuration API. To configure a public privacy contact, set `server.contact.dpo.name` and `server.contact.dpo.email`; the DPO page falls back to `server.contact.general.email` and never exposes the admin address.

I2P is enabled with `server.i2p.enabled`, `I2P_ENABLED`, or `--i2p` (use `--i2p=false` to opt out). It defaults off on local machines and on in application containers. The server prefers its own dedicated `i2pd` process, then falls back to the SAM bridge at `127.0.0.1:7656`. I2P settings hot-reload by closing and restarting the eepsite with the new settings. The persistent destination key is stored under `{data_dir}/i2p/site/`; the generated `.b32.i2p` hostname remains stable across restarts. Set `server.i2p.expose: true` to include that address in autodiscovery and the public help/footer.

Use `server.contact.security.email` for the optional security-reporting email address. `web.security.report_url` defaults to the repository's private vulnerability reporting page; `web.security.policy` is an optional Markdown override. The generated `/.well-known/security.txt` also publishes the security policy URL and expiry date.

## Database

SQLite is the default local database. Remote libsql/Turso is also supported. PostgreSQL and MySQL are not supported. Schema creation and additive updates run automatically at startup.

## Secrets and backups

Keep `secrets.yml` and `server.yml` readable only by the service operator.
Never commit configuration containing secrets. Manual backups prompt for an
optional password; restore prompts when the selected archive is encrypted.
`CASWHOIS_BACKUP_PASSWORD` can provide the backup or restore password for
non-interactive operation.

Generated installation and encryption secrets are rotated with the
`--maintenance 'secret rotate …'` commands. Previous signing material remains
valid for seven days; previous encryption material is retained for 30 days
while database values are re-encrypted.

## Paths

Default paths depend on operating system and whether the process runs as root or as a user. The `--config`, `--data`, `--cache`, `--log`, and `--backup` options can override the corresponding locations. Docker uses `/config` and `/data` inside the container.

## Reloading

The server watches configuration for supported hot-reloadable settings. Settings requiring restart are identified in the server output. Restart the service after changing listener, database, TLS, or other startup-only values.

See [CLI Reference](cli.md) for command-line options and [Installation](installation.md) for service setup.
