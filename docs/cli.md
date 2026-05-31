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
| `--color` | string | auto | Colour output: `always`, `never`, or `auto` |
| `--lang` | string | `en` | Language: `en`, `es`, `zh`, `fr`, `ar`, `de`, `ja` |
| `--shell` | string | — | Print shell completions: `bash`, `zsh`, or `fish` |
| `--cache DIR` | string | OS default | Cache directory |
| `--backup DIR` | string | OS default | Backup directory |
| `--pid FILE` | string | OS default | PID file path |
| `--baseurl URL` | string | — | Base URL override |

## Service Management

```
caswhois --service <cmd>
```

| Command | Description |
|---------|-------------|
| `install` | Install as system service and start |
| `uninstall` | Stop, disable, and remove service unit file |
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
| `update` | Alias for `--update yes` |
| `help` | Show maintenance subcommand help |

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
caswhois --shell bash >> ~/.bash_completion

# Zsh
caswhois --shell zsh >> ~/.zshrc

# Fish
caswhois --shell fish > ~/.config/fish/completions/caswhois.fish
```

## Version Output

```
caswhois version 0.1.0
Commit: abc1234
Built:  2026-05-30T00:00:00Z
Site:   https://github.com/casapps/caswhois
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
| Config | `/etc/casapps/caswhois/` |
| Data | `/var/lib/casapps/caswhois/` |
| Logs | `/var/log/casapps/caswhois/` |

### Linux (running as user)

| Purpose | Path |
|---------|------|
| Config | `~/.config/casapps/caswhois/` |
| Data | `~/.local/share/casapps/caswhois/` |
| Logs | `~/.local/share/casapps/caswhois/logs/` |

### Container

| Purpose | Path |
|---------|------|
| Config | `/config/` |
| Data | `/data/` |
| Logs | `/data/logs/` |
