# Installation

caswhois is distributed as a static binary and as a Docker image. On first start it creates its configuration and data directories and writes generated credentials to `secrets.yml`.

## Binary

Download the release asset for your operating system and architecture from the [GitHub releases page](https://github.com/apimgr/whois/releases). Verify its published checksum before running it, then:

```bash
chmod +x caswhois-linux-amd64
./caswhois-linux-amd64 --help
./caswhois-linux-amd64
```

The default listener port is selected on first run in the configured range; check startup output or `server.yml` for the actual value. Visit the printed local URL to use the WHOIS lookup page. The operator token and encryption secret are stored in `secrets.yml` and must be protected.

## Docker

Use the repository's production compose file from a deployment directory, or run the published image with persistent mounts for `/config` and `/data`:

```bash
docker run -d --name caswhois \
  -p 64580:64580 \
  -v caswhois-config:/config \
  -v caswhois-data:/data \
  ghcr.io/apimgr/whois:latest
```

The selected host port must match the listener configuration. Protect the mounted configuration and data because they contain operator secrets and the accumulated WHOIS dataset.

## Service installation

The binary provides service-management commands for supported platforms. Review the command help for the current platform before installing:

```bash
caswhois --service help
```

Run the service as an unprivileged account where possible. Keep its config, data, logs, cache, and backup paths writable only by the service and administrators.

## Supported platforms

Release builds target Linux, macOS, Windows, and FreeBSD on amd64 and arm64. Confirm the release page for available artifacts.

## Build from source

The repository's Makefile uses Docker for Go builds and tests. See [Development](development.md) for the supported workflow.
