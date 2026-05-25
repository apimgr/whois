# Admin Guide

## Admin Panel Access

The admin panel is available at:

```
https://your-domain.com/admin
```

Default admin path is `/admin` but can be customized in configuration.

## First-Time Setup

### Initial Setup Wizard

On first run, the server generates a setup token displayed in the console:

```
╔══════════════════════════════════════════════════════════════╗
║                        CASWHOIS                               ║
║                                                               ║
║  Setup Token: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p               ║
║  Setup URL: http://localhost:64580/admin/server/setup        ║
╚══════════════════════════════════════════════════════════════╝
```

Navigate to the setup URL and complete the wizard:

1. **Create Primary Admin**
   - Username
   - Email
   - Password (Argon2id hashed)
   
2. **Server Configuration**
   - Server name
   - Port and address
   - Mode (production/development)

3. **Email Setup** (optional)
   - SMTP settings
   - Test email delivery

4. **Backup Configuration** (optional)
   - Enable automatic backups
   - Set encryption password
   - Configure retention policy

The setup token is deleted after successful completion.

## Dashboard

The dashboard provides an overview of your server:

### System Status

- **Health:** Database, cache, disk, scheduler status
- **Uptime:** Server uptime and version
- **Resources:** CPU, memory, disk usage
- **Connections:** Active connections and requests

### Recent Activity

- Recent WHOIS lookups
- Recent admin actions
- System events

### Quick Actions

- Create backup
- Restart server
- Clear cache
- View logs

## Server Management

### Server Settings

**Location:** `/admin/server/settings`

#### General Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Server Name | Display name | CASWHOIS |
| Admin Path | Admin panel URL path | `admin` |
| Port | HTTP port | 64580 |
| Address | Listen address | `0.0.0.0` |
| Mode | Application mode | `production` |

#### Security Settings

| Setting | Description |
|---------|-------------|
| Rate Limiting | Enable/disable rate limiting |
| Session Timeout | Session expiration time |
| Remember Me | Allow "remember me" feature |
| 2FA | Enable two-factor authentication |

#### Email Settings

| Setting | Description |
|---------|-------------|
| SMTP Host | Mail server hostname |
| SMTP Port | Mail server port (587, 465) |
| Username | SMTP authentication username |
| Password | SMTP authentication password |
| From Address | Sender email address |
| From Name | Sender display name |

Test email functionality with the "Send Test Email" button.

### SSL/TLS Configuration

**Location:** `/admin/server/ssl`

#### Manual Certificates

1. Upload certificate file (PEM format)
2. Upload private key file (PEM format)
3. Enable SSL
4. Test configuration

#### Let's Encrypt

1. Enter email address
2. Add domains (one per line)
3. Choose challenge type:
   - HTTP-01 (port 80 required)
   - TLS-ALPN-01 (port 443 required)
   - DNS-01 (DNS provider required)
4. Enable Let's Encrypt
5. Server automatically obtains and renews certificates

**Auto-renewal:** Certificates are automatically renewed 30 days before expiration.

### Backup & Restore

**Location:** `/admin/server/backup`

#### Create Backup

1. Choose backup type:
   - **Full:** Database + config + uploads
   - **Database Only:** Database only
   - **Config Only:** Configuration files only
   
2. Enable encryption (optional but recommended)
3. Click "Create Backup"

Backup filename: `caswhois-{type}-{timestamp}.tar.gz[.enc]`

#### Automatic Backups

Configure automatic backups:

| Setting | Description | Default |
|---------|-------------|---------|
| Enable | Auto-backup on schedule | true |
| Schedule | Cron expression | `0 2 * * *` (daily 2am) |
| Retention | Max backups to keep | 7 |
| Weekly | Keep weekly backups | 4 |
| Monthly | Keep monthly backups | 12 |
| Yearly | Keep yearly backups | 0 |
| Encryption | Encrypt backups | false |

#### Restore Backup

1. Upload backup file
2. Enter encryption password (if encrypted)
3. Review backup contents
4. Click "Restore"
5. Server restarts automatically

**Warning:** Restore overwrites current data. Create a backup first!

### Logs

**Location:** `/admin/server/logs`

View and download server logs:

| Log Type | Description |
|----------|-------------|
| Server | General server logs |
| Access | HTTP access logs |
| Error | Error logs |
| Audit | Security and admin actions |

**Log Levels:** debug, info, warn, error

**Actions:**
- View logs in browser
- Download log file
- Clear logs (keeps last 1000 lines)
- Change log level

### Updates

**Location:** `/admin/server/updates`

#### Check for Updates

Click "Check for Updates" to query GitHub releases for new versions.

#### Update Channels

| Channel | Description | Stability |
|---------|-------------|-----------|
| Stable | Production releases | Recommended |
| Beta | Pre-release versions | Testing |
| Daily | Nightly builds | Development |

#### Update Process

1. Backup automatically created
2. New binary downloaded
3. Verification (checksum, signature)
4. Binary replaced
5. Server restart

**Rollback:** If update fails, previous version is restored automatically.

## Admin Management

### Admin Accounts

**Location:** `/admin/admins`

#### Create Admin

1. Click "Add Admin"
2. Enter details:
   - Username
   - Email
   - Password
3. Choose role:
   - **Primary Admin:** Full access, cannot be deleted
   - **Admin:** Full access, can be deleted
4. Click "Create"

#### Edit Admin

- Change password
- Update email
- Enable/disable 2FA
- View last login
- View API tokens

#### Delete Admin

**Warning:** Primary admin cannot be deleted. At least one admin must exist.

### Admin Tokens

**Location:** `/admin/tokens`

#### Create Token

1. Click "Create Token"
2. Enter details:
   - Name (e.g., "ci-cd", "monitoring")
   - Scope (global, read-write, read)
   - Expiration (never, 7d, 1m, 6m, 1y, custom)
3. Click "Create"
4. **Copy token immediately** - it's shown only once

Token format: `adm_{32_random_chars}`

#### Manage Tokens

- View all tokens (last 8 chars shown)
- Check last used timestamp
- Rotate token (new value, keep settings)
- Delete token (immediate revocation)

### Two-Factor Authentication

**Location:** `/admin/profile/2fa`

#### Enable 2FA

1. Click "Enable 2FA"
2. Choose method:
   - **TOTP** (Time-based One-Time Password)
   - **WebAuthn** (Hardware key, biometric)
3. Follow setup instructions
4. Save recovery codes (10 codes provided)

#### Trusted Devices

Enable "Remember this device" during login to skip 2FA for 30 days (configurable).

View and manage trusted devices in profile settings.

## Monitoring & Metrics

### Metrics Dashboard

**Location:** `/admin/metrics`

View real-time metrics:

- **Requests:** Total, per endpoint, per hour
- **Response Times:** Average, p50, p95, p99
- **Errors:** Count by type
- **System:** CPU, memory, disk, goroutines
- **Cache:** Hit rate, size, evictions

### Prometheus Metrics

Available at `/metrics` (authentication optional):

```
# Server metrics
caswhois_requests_total{method="GET",path="/api/v1/whois/domain",status="200"} 1234

# System metrics
caswhois_system_memory_used_bytes 52428800
caswhois_go_goroutines 45

# Cache metrics
caswhois_cache_hits_total{cache="whois"} 890
caswhois_cache_misses_total{cache="whois"} 110
```

Import into Grafana or other monitoring tools.

## Scheduler Management

**Location:** `/admin/scheduler`

View and manage scheduled tasks:

| Task | Schedule | Description |
|------|----------|-------------|
| backup_daily | `0 2 * * *` | Daily backup at 2am |
| ssl_renewal | `0 3 * * *` | Check SSL certificate expiration |
| geoip_update | `0 3 * * 0` | Update GeoIP database (Sunday 3am) |
| session_cleanup | `0 * * * *` | Remove expired sessions (hourly) |
| cache_cleanup | `0 4 * * *` | Clean old cache entries |

**Actions:**
- Enable/disable task
- Run task now
- View last run time
- View next run time
- Edit schedule (cron expression)

## Database Management

### Database Info

**Location:** `/admin/server/database`

View database statistics:

- Database type (SQLite, PostgreSQL, MySQL)
- Size
- Table count
- Record counts
- Index statistics

### Database Operations

- **Vacuum:** Optimize database (SQLite only)
- **Analyze:** Update query statistics
- **Backup:** Create database-only backup

**Warning:** These operations may briefly lock the database.

## Advanced Settings

### Cluster Mode

**Location:** `/admin/server/cluster`

Configure multi-node cluster:

1. Enable cluster mode
2. Set node ID
3. Add node URLs
4. Configure health check interval
5. Enable failover

**Node Types:**
- **Primary:** Handles writes, coordinates cluster
- **Replica:** Read-only, syncs from primary

### Tor Hidden Service

**Location:** `/admin/server/tor`

**Auto-enabled** when `tor` binary is found in PATH.

Settings:
- Enable/disable Tor
- View .onion address
- Generate vanity address (custom prefix)
- Tor status and logs

### GeoIP

**Location:** `/admin/server/geoip`

Configure IP geolocation:

- Enable/disable GeoIP
- Auto-update database
- Update schedule
- Manual update
- View database version

### Rate Limiting

**Location:** `/admin/server/ratelimit`

Configure rate limits:

| Endpoint Type | Requests/Minute | Burst |
|---------------|-----------------|-------|
| Anonymous | 30 | 5 |
| Authenticated | 60 | 10 |
| Admin | 120 | 20 |

Customize per-endpoint limits if needed.

## Troubleshooting

### Server Won't Start

1. Check logs: `journalctl -u caswhois -f`
2. Verify port not in use: `netstat -tuln | grep 64580`
3. Check permissions on config/data directories
4. Review configuration file for errors

### Can't Access Admin Panel

1. Verify server is running: `caswhois --status`
2. Check admin_path setting in config
3. Try default path: `/admin`
4. Check firewall rules

### Forgot Admin Password

Use the CLI to reset:

```bash
caswhois --maintenance setup
```

This regenerates the setup token and allows creating a new admin account.

### Backup Fails

1. Check disk space: `df -h`
2. Verify backup directory is writable
3. Check logs for specific error
4. Try manual backup: `caswhois --maintenance backup`

### SSL Certificate Issues

1. Verify domain DNS points to server
2. Check firewall allows ports 80/443
3. Review Let's Encrypt logs
4. Test with manual certificates first

## Security Best Practices

1. **Use strong passwords** - Minimum 12 characters, mixed case, numbers, symbols
2. **Enable 2FA** - All admin accounts should use two-factor authentication
3. **Rotate tokens** - Create new API tokens periodically
4. **Enable SSL** - Always use HTTPS in production
5. **Regular backups** - Daily encrypted backups minimum
6. **Update regularly** - Apply security updates promptly
7. **Monitor logs** - Review audit logs for suspicious activity
8. **Limit access** - Use read-only tokens where possible

## Support

- **Documentation:** [https://caswhois.readthedocs.io](https://caswhois.readthedocs.io)
- **API Reference:** [/openapi](/openapi)
- **Health Check:** [/healthz](/healthz)
