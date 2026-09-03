# Configuration

## Configuration File

The server uses `server.yml` in the config directory.

**Default Locations:**

| OS | Config Path |
|----|-------------|
| Linux (root) | `/etc/apimgr/caswhois/server.yml` |
| Linux (user) | `~/.config/apimgr/caswhois/server.yml` |
| macOS | `~/Library/Application Support/apimgr/caswhois/server.yml` |
| Windows | `%APPDATA%\apimgr\caswhois\server.yml` |
| Docker | `/config/server.yml` |

## Configuration Hierarchy

Settings are applied in this order (later overrides earlier):

1. **Defaults** - Built-in defaults
2. **Config File** - `server.yml`
3. **Environment Variables** - `CASWHOIS_*`
4. **CLI Flags** - `--port`, `--address`, etc.

## Example Configuration

```yaml
# Server settings
server:
  address: 0.0.0.0
  port: 64580
  mode: production
  admin_path: admin

# Database
database:
  type: sqlite  # sqlite, postgres, mysql
  path: /data/caswhois.db

# SSL/TLS
ssl:
  enabled: false
  cert_file: /config/ssl/cert.pem
  key_file: /config/ssl/key.pem
  auto_redirect: true

# Let's Encrypt
letsencrypt:
  enabled: false
  email: admin@example.com
  domains:
    - example.com
    - www.example.com
  challenge: http-01  # http-01, tls-alpn-01, dns-01

# Email
email:
  enabled: false
  smtp_host: smtp.example.com
  smtp_port: 587
  smtp_user: user@example.com
  smtp_pass: password
  from_address: noreply@example.com
  from_name: CASWHOIS

# Logging
logging:
  level: info  # debug, info, warn, error
  format: json  # json, text
  output: stdout  # stdout, file
  file: /var/log/apimgr/caswhois/server.log

# Rate Limiting
ratelimit:
  enabled: true
  requests_per_minute: 60
  burst: 10

# GeoIP
geoip:
  enabled: true
  auto_update: true
  update_schedule: "0 3 * * 0"  # Weekly at 3am Sunday

# Metrics
metrics:
  enabled: true
  path: /metrics
  auth_required: false

# Backup
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2am
  retention:
    max_backups: 7
    keep_weekly: 4
    keep_monthly: 12
    keep_yearly: 0
  encryption:
    enabled: false
    password: ""  # Set via admin panel or CASWHOIS_BACKUP_PASSWORD

# Scheduler
scheduler:
  enabled: true

# Cluster (optional)
cluster:
  enabled: false
  primary_url: http://primary:64580
  nodes:
    - http://node1:64580
    - http://node2:64580

# Tor Hidden Service (auto-enabled if tor binary found)
tor:
  enabled: false  # Set to true to enable even without tor binary
  vanity_prefix: ""  # Optional: generate vanity .onion address
```

## Environment Variables

All configuration options can be set via environment variables:

```bash
# Format: CASWHOIS_{SECTION}_{KEY}
export CASWHOIS_SERVER_PORT=8080
export CASWHOIS_SERVER_ADDRESS=127.0.0.1
export CASWHOIS_DATABASE_TYPE=postgres
export CASWHOIS_DATABASE_DSN="postgresql://user:pass@localhost/caswhois"
export CASWHOIS_SSL_ENABLED=true
export CASWHOIS_EMAIL_SMTP_HOST=smtp.example.com
```

**Boolean values:** `true`, `false`, `yes`, `no`, `1`, `0`, `on`, `off`

## CLI Flags

Override any setting with CLI flags:

```bash
caswhois --port 8080 --address 127.0.0.1 --mode development
```

## Database Configuration

### SQLite (Default)

```yaml
database:
  type: sqlite
  path: /data/caswhois.db
```

### PostgreSQL

```yaml
database:
  type: postgres
  dsn: postgresql://user:password@localhost:5432/caswhois?sslmode=disable
  max_connections: 25
  max_idle: 5
  max_lifetime: 5m
```

### MySQL

```yaml
database:
  type: mysql
  dsn: user:password@tcp(localhost:3306)/caswhois?parseTime=true
  max_connections: 25
  max_idle: 5
  max_lifetime: 5m
```

## SSL/TLS Configuration

### Manual Certificates

```yaml
ssl:
  enabled: true
  cert_file: /config/ssl/cert.pem
  key_file: /config/ssl/key.pem
  auto_redirect: true  # Redirect HTTP to HTTPS
```

### Let's Encrypt

```yaml
letsencrypt:
  enabled: true
  email: admin@example.com
  domains:
    - example.com
    - www.example.com
  challenge: http-01  # or tls-alpn-01, dns-01
  staging: false  # Use Let's Encrypt staging for testing
```

## Security Configuration

### Password Policy

```yaml
security:
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true
    complexity: 3  # Minimum character types required
    expiry_days: 0  # 0 = never expire
    history: 0  # Password history count
```

### Session Configuration

```yaml
security:
  sessions:
    timeout: 30m  # Session timeout
    remember_me: true
    remember_duration: 720h  # 30 days
```

### CORS Configuration

```yaml
security:
  cors:
    enabled: true
    allowed_origins:
      - https://example.com
    allowed_methods:
      - GET
      - POST
      - PUT
      - DELETE
    allowed_headers:
      - Authorization
      - Content-Type
    expose_headers:
      - X-Total-Count
    allow_credentials: true
    max_age: 3600
```

## Advanced Configuration

### Cluster Mode

```yaml
cluster:
  enabled: true
  node_id: node1
  primary_url: http://primary:64580
  nodes:
    - http://node1:64580
    - http://node2:64580
    - http://node3:64580
  health_check_interval: 30s
  failover_enabled: true
```

### Custom Cache

```yaml
cache:
  type: memory  # memory, valkey, redis
  ttl: 1h
  max_items: 10000
  
  # Valkey/Redis configuration
  valkey:
    address: localhost:6379
    password: ""
    db: 0
```

### Compliance Mode

```yaml
compliance:
  enabled: false  # Enable for GDPR, HIPAA, etc.
  standards:
    - gdpr
    - ccpa
  data_retention_days: 90
  encryption_required: true
```

## Validation

The server validates configuration on startup. Unknown keys cause errors (not warnings).

```bash
# Test configuration
caswhois --config /path/to/config --help
```

## Reloading Configuration

Some settings can be reloaded without restart:

```bash
# Send SIGHUP signal
kill -HUP $(pidof caswhois)

# Or use service command
caswhois --service reload
```

**Hot-reloadable settings:** logging level, rate limits, email settings

**Requires restart:** port, address, database, SSL settings

## Configuration via Admin Panel

Most settings can be configured via the web admin panel at `/{admin_path}/server/settings`.

Changes made via admin panel are saved to `server.yml`.

## Troubleshooting

### Invalid Configuration

Check logs for specific validation errors:

```bash
journalctl -u caswhois | grep error
```

### Permission Denied

Ensure config directory is writable:

```bash
sudo chown -R caswhois:caswhois /etc/apimgr/caswhois
```

### Environment Variables Not Working

Check variable names - they must match exactly:

```bash
env | grep CASWHOIS
```

## Next Steps

- [Admin Guide](admin.md) - Manage your instance
- [API Documentation](api.md) - API reference
- [Development](development.md) - Development guide
