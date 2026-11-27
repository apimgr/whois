# CLI Reference

## Binary: `caswhois`

The main server binary. All flags are optional; defaults are loaded from `server.yml` in the config directory.

## Global Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-h`, `--help` | — | — | Print help and exit |
| `-v`, `--version` | — | — | Print version info and exit |
| `--status` | — | — | Health check; exit 0=healthy, 1=unhealthy |
| `--mode` | string | `production` | Run mode: `production` or `development` |
| `--config DIR` | string | OS default | Config directory |
| `--data DIR` | string | OS default | Data directory |
| `--log DIR` | string | OS default | Log directory |
| `--address ADDR` | string | `[::]` | Listen address |
| `--port PORT` | string | auto | Listen port or `HTTP,HTTPS` port pair (default: random 64000–64999) |
| `--i2p[=BOOL]` | bool | config-dependent | Enable the I2P eepsite; accepts `--i2p=false` to disable it |
| `--daemon` | — | — | Detach from terminal (not applicable in containers) |
| `--debug` | — | — | Enable debug logging |
| `--color` | string | auto | Colour output: `auto`, `yes`, or `no` (`--no-color` is an alias for `no`) |
| `--lang` | string | auto | Language for output; falls back to English when no supported `LANG` value is found |
| `--shell` | string | — | Shell integration: `completions` or `init`, optionally followed by `bash`, `zsh`, or `fish` |
| `--cache DIR` | string | OS default | Cache directory |
| `--backup DIR` | string | OS default | Backup directory |
| `--pid FILE` | string | OS default | PID file path |
| `--baseurl PATH` | string | — | URL path prefix served by the application |
| `--service CMD` | string | — | Service action: install, uninstall, disable, start, stop, restart, reload, status |
| `--maintenance CMD` | string | — | Maintenance action (see below) |
| `--update CMD` | string | — | Update action: `check`, `yes`, or `branch stable|beta|daily` |

The same server operations are available as positional commands: `serve`, `version`, `migrate`, `client`, `install`, `uninstall`, `start`, `stop`, `restart`, `status`, `update`, and `scheduler`. Run `caswhois <command> --help` where supported for command-specific usage.

## Service Management

```bash
caswhois --service=start
caswhois --service --install
```

| Command | Description |
|---------|-------------|
| `--install` | Install, enable, and start service |
| `--uninstall` | Stop and remove the service, then delete configured application directories and any service account created by the installer; keeps the binary |
| `disable` | Disable service startup |
| `start` | Start the installed service |
| `stop` | Stop the running service |
| `restart` | Restart the service |
| `reload` | Reload configuration without restart |
| `status` | Show current service status |
| `help` | Show service subcommand help |

Service management writes the appropriate unit file for the detected init system (systemd, OpenRC, runit, s6, launchd, or Windows SCM).

## Maintenance

```
caswhois --maintenance <cmd>
```

| Command | Description |
|---------|-------------|
| `backup` | Create and verify a backup using the configured encryption password |
| `backup test [FILE]` | Verify an existing backup; defaults to the newest full backup |
| `restore [FILE]` | Restore the selected archive, or the newest full when omitted; asks for typed confirmation |
| `mode production\|development` | Change the configured server mode |
| `setup` | Reset server configuration to defaults (root only) |
| `pgp generate\|rotate\|publish\|export\|import\|delete` | Manage the PGP keypair |
| `secret rotate installation_secret\|encryption_key` | Rotate a generated signing or at-rest encryption secret; requires operator authorization, a reason, and typed confirmation |
| `token list\|revoke PREFIX` | List or revoke the current resource-bound token records |
| `data export [IP]\|delete IP` | Export or anonymize stored requester data |
| `compliance report` | Print the compliance summary |
| `tor status` | Show Tor process, onion address, bootstrap, circuit, and vanity-search status |
| `tor validate` | Validate the Tor configuration without changing server state |
| `tor restart` | Restart the running embedded Tor process |
| `tor regenerate` | Replace the onion service keys and address after confirmation |
| `tor vanity start --prefix PREFIX [--workers N]` | Search for an onion address beginning with a 1–6 character base32 prefix |
| `tor vanity stop` | Cancel a running vanity search; found candidates are retained |
| `tor vanity apply [ADDRESS]` | Activate a saved vanity candidate after confirmation |
| `tor import-keys PATH` | Import an existing Tor hidden-service key directory after confirmation |
| `update [CMD]` | Alias for the update operation |
| `help` | Show maintenance command help |

Tor maintenance commands control the embedded Tor process through the server's
loopback-only control channel. Status and validation can read local state when
the server is stopped; actions that change Tor state require the server to be
running. Regenerating or applying an address stops the previous onion address
from working. Vanity searches run in the server process and do not survive a
server restart, though saved candidates remain available.

Tor maintenance requires root or the operator token. `regenerate`,
`vanity apply`, and `import-keys` also prompt for the exact confirmation; pass
`--yes` to skip that confirmation in a controlled script. Key imports require
an absolute directory path. For example:

```sh
caswhois --maintenance tor status
caswhois --maintenance tor vanity start --prefix abc --workers 2
caswhois --maintenance tor vanity apply
caswhois --maintenance tor import-keys /path/to/hidden-service-keys
```

## Updates

```
caswhois --update <cmd>
```

| Command | Description |
|---------|-------------|
| `check` | Check for a newer release on GitHub |
| `yes` | Download and replace the binary in-place |
| `branch NAME` | Switch update channel: `stable`, `beta`, or `daily` |
| `help` | Show update subcommand help |

## Shell Completions

Generate shell completions and add them to your shell profile:

```bash
# Bash
caswhois --shell completions bash >> ~/.bash_completion

# Zsh
caswhois --shell completions zsh >> ~/.zshrc

# Fish
caswhois --shell completions fish > ~/.config/fish/completions/caswhois.fish
```

To print the shell's initialization command instead, use `caswhois --shell init bash`, `caswhois --shell init zsh`, or `caswhois --shell init fish`.

## Companion Client

`caswhois-cli` supports `domain`, `ip`, `asn`, `lookup`, and `validate` commands, or a query directly for automatic type detection. `--server URL` selects the server; `--token` or `--token-file` supplies an API token when an endpoint requires one. Output formats are `json`, `table`, and `plain`. See `caswhois-cli --help` for the flags and environment variables accepted by the installed version.

The client reads the server's API version from `/api/autodiscover` on its first lookup or validation request, then uses that version for the lifetime of the client process.

## Version Output

```
caswhois version 0.1.0
Commit: abc1234
Built:  2026-05-30T00:00:00Z
Site:   https://github.com/apimgr/whois
```

## Environment Variables

| Variable | Overrides |
|----------|-----------|
| `NO_COLOR` | Disable all colour output (any non-empty value) |
| `TERM` | Disable colour output when set to `dumb` |
| `PORT` | Override the HTTP listener port |
| `LISTEN` | Override the listener address |
| `I2P_ENABLED` | Override whether the I2P eepsite is enabled |
| `MODE` | Override run mode |
| `DEBUG` | Enable debug mode when set to `1`, `true`, or `yes` |
| `CONFIG_DIR` | Override config directory |
| `DATA_DIR` | Override data directory |
| `LOG_DIR` | Override log directory |
| `BACKUP_DIR` | Override backup directory |
| `APPLICATION_NAME` | Override the displayed application name |
| `APPLICATION_TAGLINE` | Override the displayed application tagline |
| `DATABASE_URL` | Remote libsql/Turso connection string |
| `DATABASE_DRIVER` | Override driver (`sqlite`) |
| `DATABASE_DIR` | Override SQLite directory |
| `SMTP_HOST` | SMTP server name |
| `SMTP_PORT` | SMTP server port |
| `SMTP_USERNAME` | SMTP auth username |
| `SMTP_PASSWORD` | SMTP auth password |
| `SMTP_TLS` | SMTP TLS mode: `auto`, `starttls`, `tls`, `none` |
| `SMTP_FROM_NAME` | Sender display name |
| `SMTP_FROM_EMAIL` | Sender email address |

## OS-Specific Default Paths

### Linux (running as root)

| Purpose | Path |
|---------|------|
| Config | `/etc/apimgr/caswhois/` |
| Data | `/var/lib/apimgr/caswhois/` |
| Logs | `/var/log/apimgr/caswhois/` |

### Linux (running as user)

| Purpose | Path |
|---------|------|
| Config | `~/.config/apimgr/caswhois/` |
| Data | `~/.local/share/apimgr/caswhois/` |
| Logs | `~/.local/share/apimgr/caswhois/logs/` |

### Container

| Purpose | Path |
|---------|------|
| Config | `/config/` |
| Data | `/data/` |
| Logs | `/data/logs/` |
