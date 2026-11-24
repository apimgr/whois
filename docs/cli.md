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
| `--address ADDR` | string | `[::]` | Listen address |
| `--port PORT` | int | auto | Listen port (64000–64999 range) |
| `--daemon` | — | — | Detach from terminal (not applicable in containers) |
| `--debug` | — | — | Enable debug logging |
| `--color` | string | auto | Colour output: `auto`, `yes`, or `no` (`--no-color` is an alias for `no`) |
| `--lang` | string | auto | Language for output; falls back to English when no supported `LANG` value is found |
| `--shell` | string | — | Shell integration: `completions` or `init`, optionally followed by `bash`, `zsh`, or `fish` |
| `--cache DIR` | string | OS default | Cache directory |
| `--backup DIR` | string | OS default | Backup directory |
| `--pid FILE` | string | OS default | PID file path |
| `--baseurl URL` | string | — | Base URL override |
| `--service CMD` | string | — | Service action: install, uninstall, disable, start, stop, restart, reload, status |
| `--maintenance CMD` | string | — | Maintenance action (see below) |
| `--update CMD` | string | — | Update action: `check`, `yes`, or `branch stable|beta|daily` |

The same server operations are available as positional commands: `serve`, `version`, `migrate`, `client`, `install`, `uninstall`, `start`, `stop`, `restart`, `status`, `update`, and `scheduler`. Run `caswhois <command> --help` where supported for command-specific usage.

## Service Management

```bash
caswhois --service=start
caswhois --service=--install
```

| Command | Description |
|---------|-------------|
| `--install` | Install, enable, and start service |
| `--uninstall` | Stop, disable, and remove the service unit (keeps the binary) |
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
| `backup` | Trigger a full backup immediately |
| `restore FILE` | Restore from the specified backup archive |
| `mode production\|development` | Change the configured server mode |
| `setup` | Reset server configuration to defaults (root only) |
| `pgp generate\|rotate\|publish\|export\|import\|delete` | Manage the PGP keypair |
| `token list\|revoke PREFIX` | List or revoke legacy resource tokens |
| `data export [IP]\|delete IP` | Export or anonymize stored requester data |
| `compliance report` | Print the compliance summary |
| `update [CMD]` | Alias for the update operation |
| `help` | Show maintenance command help |

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
| `DATABASE_URL` | Remote libsql/Turso connection string |
| `DATABASE_DRIVER` | Override driver (`sqlite`) |
| `DATABASE_DIR` | Override SQLite directory |
| `SMTP_HOST` | SMTP server host |
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
