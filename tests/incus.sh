#!/usr/bin/env bash
set -eo pipefail

# Check if incus is available
if ! command -v incus &>/dev/null; then
    echo "ERROR: incus not found. Install incus or use tests/docker.sh" >&2
    exit 69
fi

# Usage: tests/incus.sh [systemd|openrc|all]   (default: all)
# systemd runs in a Debian container, openrc in an Alpine container; each gets the full test run
MODE="${1:-all}"
case "$MODE" in
    systemd|openrc) MODES="$MODE" ;;
    all) MODES="systemd openrc" ;;
    *) echo "Usage: $0 [systemd|openrc|all]" >&2; exit 2 ;;
esac

# Detect project info
PROJECT_NAME="${PROJECT_NAME:-$(sed -n 's/^project_name:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')}"
PROJECT_ORG="${PROJECT_ORG:-$(sed -n 's/^project_org:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')}"
INTERNAL_NAME="${INTERNAL_NAME:-$(sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')}"
INTERNAL_ORG="${INTERNAL_ORG:-$(sed -n 's/^internal_org:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')}"
API_VERSION="${API_VERSION:-$(sed -n 's/^api_version:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')}"
CONTAINER_PREFIX="${PROJECT_NAME}-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8)"
CONTAINERS=()
BUILD_ROOT=""

# Incus images, one per init system: systemd uses the latest Debian stable, OpenRC uses the
# latest stable Alpine release (update both when new stable releases ship)
INCUS_IMAGE_SYSTEMD="images:debian/trixie"
INCUS_IMAGE_OPENRC="images:alpine/3.24"

# Resource caps for every instance (the counterparts of DOCKER_CPUS and DOCKER_MEM); override from the environment
INCUS_CPUS="${INCUS_CPUS:-2}"
INCUS_MEM="${INCUS_MEM:-4GiB}"

# CPU priority for a container (0 lowest, 10 highest, the Incus default); only matters while CPU is contended
INCUS_CPU_PRIORITY="${INCUS_CPU_PRIORITY:-2}"

# Ceilings in seconds: one quick exec step, a package install, and the whole remote test run; override from the environment
INCUS_OP_TIMEOUT="${INCUS_OP_TIMEOUT:-60}"
INCUS_INSTALL_TIMEOUT="${INCUS_INSTALL_TIMEOUT:-900}"
INCUS_RUN_TIMEOUT="${INCUS_RUN_TIMEOUT:-3600}"

cleanup() {
    local c
    for c in "${CONTAINERS[@]}"; do incus delete "$c" --force 2>/dev/null || true; done
    if [ -n "$BUILD_ROOT" ]; then
        rm -rf -- "$BUILD_ROOT"
    fi
}
trap cleanup EXIT INT TERM

TEMP_PARENT="${TMPDIR:-/tmp}/$PROJECT_ORG"
mkdir -p "$TEMP_PARENT"
BUILD_ROOT="$(mktemp -d "$TEMP_PARENT/$INTERNAL_NAME-XXXXXX")"
chmod 0700 "$BUILD_ROOT"
BIN_DIR="$BUILD_ROOT/binaries"
RELEASE_DIR="$BUILD_ROOT/releases"

# Build — use Makefile if present (standard for all bootstrapped projects)
# Output always lands in $BIN_DIR
if [ -f "Makefile" ]; then
    echo "Building with make build..."
    make build BINDIR="$BIN_DIR" RELDIR="$RELEASE_DIR"
else
    # No Makefile yet — fallback to direct docker run
    echo "Building in Docker (no Makefile)..."
    GO_CACHE="${GO_CACHE:-$HOME/go/pkg/mod}"
    GO_BUILD="${GO_BUILD:-$HOME/.cache/go-build/${PROJECT_NAME}}"
    mkdir -p "$GO_CACHE" "$GO_BUILD" "$BIN_DIR"
    docker run --rm \
      --name "${PROJECT_NAME}-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8)" \
      -v "$PWD:/app" \
      -v "$GO_CACHE:/usr/local/share/go/pkg/mod" \
      -v "$GO_BUILD:/usr/local/share/go/cache" \
      -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
      casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o "/app/${BIN_DIR}/${PROJECT_NAME}" ./src
    if [ -d "src/client" ]; then
        docker run --rm \
          --name "${PROJECT_NAME}-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8)" \
          -v "$PWD:/app" \
          -v "$GO_CACHE:/usr/local/share/go/pkg/mod" \
          -v "$GO_BUILD:/usr/local/share/go/cache" \
          -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
          casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o "/app/${BIN_DIR}/${PROJECT_NAME}-cli" ./src/client
    fi
fi

REMOTE_LIB=$(cat <<'REMOTE_LIB_EOF'
INTERNAL_NAME="${INTERNAL_NAME:-$PROJECT_NAME}"
INTERNAL_ORG="${INTERNAL_ORG:-$PROJECT_ORG}"
FAILURES=0
fail() { echo "✗ FAILED: $*" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "✓ $*"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
check_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }
wait_for() { local n="$1" i; shift; for i in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

# A native service listens on the port the server saved in server.yml (a random 64xxx port; 80 is only the container default), so read it there
CONFIG_FILE="/etc/${INTERNAL_ORG}/${INTERNAL_NAME}/server.yml"
# Only the direct server.port key is relevant; nested service ports must not be mistaken for the listener.
port() { awk '/^server:/ {s=1; next} /^[^[:space:]#]/ {s=0} s && /^    port:/ {v=$2; gsub(/[^0-9,]/, "", v); sub(/,.*/, "", v); print v; exit}' "$CONFIG_FILE" 2>/dev/null; }
api() { echo "http://localhost:$(port)/api/${API_VERSION}/server/healthz"; }
# The health helper asks for JSON: without an Accept header a curl client gets plain text and every jq check below would fail
healthz() { curl -q -LSsf --max-time 10 -H 'Accept: application/json' "$(api)"; }
healthz_up() { healthz | jq -e '.status' >/dev/null; }
overlay() { healthz | jq -r ".features.$1.$2"; }

# One set of service helpers per init system; the test steps are identical for both
if [ "$INIT_MODE" = "systemd" ]; then
    UNIT_FILE="/etc/systemd/system/${INTERNAL_NAME}.service"
    svc_active()  { systemctl is-active --quiet "$INTERNAL_NAME"; }
    svc_enabled() { systemctl is-enabled --quiet "$INTERNAL_NAME"; }
    svc_pid()     { systemctl show -p MainPID --value "$INTERNAL_NAME"; }
else
    UNIT_FILE="/etc/init.d/${INTERNAL_NAME}"
    svc_active()  { rc-service "$INTERNAL_NAME" status 2>&1 | grep -q started; }
    svc_enabled() { rc-update show default | grep -qw "$INTERNAL_NAME"; }
    svc_pid()     { cut -d: -f1 "/var/run/${INTERNAL_ORG}/${INTERNAL_NAME}/${INTERNAL_NAME}.pid"; }
fi
svc_identity() {
    local pid
    pid=$(svc_pid)
    if [ -r "/proc/${pid}/stat" ]; then
        awk '{print $1 ":" $22}' "/proc/${pid}/stat"
    else
        printf '%s\n' "$pid"
    fi
}
svc_stopped() { ! svc_active; }
REMOTE_LIB_EOF
)

REMOTE_MAIN=$(cat <<'REMOTE_MAIN_EOF'
echo "=== [$INIT_MODE] Init system identity ==="
if [ "$INIT_MODE" = "systemd" ]; then
    check "PID 1 is systemd" test "$(cat /proc/1/comm)" = "systemd"
else
    check "OpenRC is running" test -d /run/openrc
    check "no systemd in this container" test ! -d /run/systemd/system
fi

echo "=== Version Check ==="
${PROJECT_NAME} --version

echo "=== Help Check ==="
${PROJECT_NAME} --help

echo "=== Binary Info ==="
ls -lh /usr/local/bin/${PROJECT_NAME}
file /usr/local/bin/${PROJECT_NAME}

echo "=== [$INIT_MODE] Service install (--service --install also enables and starts) ==="
${PROJECT_NAME} --service --install
check "service file installed at ${UNIT_FILE}" test -f "$UNIT_FILE"
if [ "$INIT_MODE" = "openrc" ]; then
    check "init script starts with #!/sbin/openrc-run" sh -c "head -1 '$UNIT_FILE' | grep '^#!/sbin/openrc-run' >/dev/null"
    check "init script is executable" test -x "$UNIT_FILE"
    check_not "init script is not a SysV script" grep -q 'BEGIN INIT INFO' "$UNIT_FILE"
    check "OpenRC supervisor uses a PID file separate from the server" grep -Fxq "pidfile=\"/var/run/${INTERNAL_ORG}-${INTERNAL_NAME}.pid\"" "$UNIT_FILE"
    check "OpenRC prepares the server PID directory" grep -Fq "checkpath -d -m 0755 -o ${INTERNAL_NAME}:${INTERNAL_NAME} /var/run/${INTERNAL_ORG}/${INTERNAL_NAME}" "$UNIT_FILE"
fi
check "service enabled at boot" svc_enabled
check "service active after install" wait_for 30 svc_active
check "health endpoint answers after install" wait_for 60 healthz_up
check "service account exists" getent passwd "$INTERNAL_NAME"
check "server runs as the service account after the privilege drop" test "$(stat -c %U /proc/$(svc_pid))" = "$INTERNAL_NAME"

echo "=== [$INIT_MODE] Service restart ==="
OLD_PID=$(svc_identity)
${PROJECT_NAME} --service restart
check "service active after restart" wait_for 30 svc_active
check "health endpoint answers after restart" wait_for 60 healthz_up
check "restart replaced the process" test "$(svc_identity)" != "$OLD_PID"

echo "=== [$INIT_MODE] Service stop and start ==="
${PROJECT_NAME} --service stop
check "service stopped" wait_for 30 svc_stopped
check_not "health endpoint is down while stopped" curl -q -LSsf --max-time 3 "$(api)"
${PROJECT_NAME} --service start
check "service active after start" wait_for 30 svc_active
check "health endpoint answers after start" wait_for 60 healthz_up

echo "=== API Endpoint Tests ==="
# JSON response (default)
curl -q -LSsf "http://localhost:$(port)/api/${API_VERSION}/server/healthz" || fail "/api/${API_VERSION}/server/healthz"
# .txt extension (plain text)
curl -q -LSsf "http://localhost:$(port)/api/${API_VERSION}/server/healthz.txt" || fail "/api/${API_VERSION}/server/healthz.txt"
# Accept: application/json
curl -q -LSsf -H 'Accept: application/json' http://localhost:$(port)/server/healthz || fail "Accept JSON"
# Accept: text/plain
curl -q -LSsf -H 'Accept: text/plain' http://localhost:$(port)/server/healthz || fail "Accept text/plain"

echo "=== Project-Specific Endpoint Tests ==="
API_ROOT="http://localhost:$(port)/api/${API_VERSION}"
check_json() {
    local label="$1" url="$2"
    if curl -q -LSsf --connect-timeout 5 --max-time 30 -H 'Accept: application/json' "$url" | jq -e '.ok == true' >/dev/null; then
        pass "$label"
    else
        fail "$label"
    fi
}
check_text() {
    local label="$1" url="$2"
    if curl -q -LSsf --connect-timeout 5 --max-time 30 -H 'Accept: text/plain' "$url" >/dev/null; then
        pass "$label"
    else
        fail "$label"
    fi
}
check_json "domain WHOIS lookup returns its JSON envelope" "$API_ROOT/whois/domain/example.com"
check_text "domain WHOIS lookup supports plain text" "$API_ROOT/whois/domain/example.com"
check_text "domain WHOIS lookup supports the .txt extension" "$API_ROOT/whois/domain/example.com.txt"
check_json "IPv4 WHOIS lookup returns its JSON envelope" "$API_ROOT/whois/ip/8.8.8.8"
check_json "ASN WHOIS lookup returns its JSON envelope" "$API_ROOT/whois/asn/AS15169"
check_json "WHOIS validation returns its JSON envelope" "$API_ROOT/whois/validate/example.com"
check_json "registrant search returns its JSON envelope" "$API_ROOT/whois/search?owner=example"

echo "=== Open API Smoke Test ==="
# No token needed for the public endpoints; MCP, metrics and token routes are checked separately (a missing token answers 401)
if curl -q -LSsf http://localhost:$(port)/server/healthz | grep '"status"' >/dev/null; then pass "Health endpoint works"; else fail "Health endpoint"; fi

echo "=== Operator-token Authorization ==="
CONF_ROOT="/etc/${INTERNAL_ORG}/${INTERNAL_NAME}"
OPERATOR_TOKEN=$(awk '/^server:/ {server=1; next} /^[^[:space:]#]/ {server=0} server && /^    token:/ {sub(/^    token:[[:space:]]*/, ""); gsub(/[\047\042]/, ""); print; exit}' "$CONF_ROOT/secrets.yml")
if [ -n "$OPERATOR_TOKEN" ]; then
    code=$(curl -q -LSs --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' "$API_ROOT/server/schedulers")
    [ "$code" = 401 ] && pass "scheduler endpoint rejects anonymous requests" || fail "scheduler endpoint anonymous status is $code, expected 401"
    code=$(curl -q -LSs --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Accept: application/json' "$API_ROOT/server/schedulers")
    [ "$code" = 200 ] && pass "operator token authorizes scheduler endpoint" || fail "scheduler endpoint operator status is $code, expected 200"
    code=$(curl -q -LSs --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' -d '{"queries":["example.com"]}' "$API_ROOT/whois/bulk")
    [ "$code" = 200 ] && pass "operator token authorizes bulk WHOIS" || fail "bulk WHOIS operator status is $code, expected 200"
else
    fail "operator token was not generated in secrets.yml"
fi

echo "=== Binary Rename Tests ==="
# Binaries show the ACTUAL name in --help/--version (not hardcoded)
cp /usr/local/bin/${PROJECT_NAME} /tmp/renamed-server
chmod +x /tmp/renamed-server
if /tmp/renamed-server --help 2>&1 | grep 'renamed-server' >/dev/null; then pass "Server binary rename works (--help shows actual name)"; else fail "Server --help does not show renamed binary name"; fi

echo "=== Client Tests (if exists) ==="
if [ -f /usr/local/bin/${PROJECT_NAME}-cli ]; then
    ${PROJECT_NAME}-cli --version || fail "CLI --version"
    ${PROJECT_NAME}-cli --help || fail "CLI --help"

    cp /usr/local/bin/${PROJECT_NAME}-cli /tmp/renamed-cli
    chmod +x /tmp/renamed-cli
    if /tmp/renamed-cli --help 2>&1 | grep 'renamed-cli' >/dev/null; then pass "CLI binary rename works"; else fail "CLI --help does not show renamed binary name"; fi

    echo '--- CLI Full Functionality Tests ---'
    if [ -n "${OPERATOR_TOKEN:-}" ]; then
        ${PROJECT_NAME}-cli --server http://localhost:$(port) --token "$OPERATOR_TOKEN" status || fail "CLI status"
        # Project-specific CLI commands go here (IDEA.md)
    else
        ${PROJECT_NAME}-cli --server http://localhost:$(port) status || echo 'CLI status (no token) failed or not applicable'
    fi
else
    echo 'client not installed - skipping'
fi

echo "=== Agent Tests (if exists) ==="

echo "=== [$INIT_MODE] Tor hidden service (tor is installed in this container) ==="
DATA_ROOT="/var/lib/${INTERNAL_ORG}/${INTERNAL_NAME}"
CONF_ROOT="/etc/${INTERNAL_ORG}/${INTERNAL_NAME}"
check "tor binary is installed" command -v tor
check "features.tor.enabled is true" test "$(overlay tor enabled)" = "true"
case "$(overlay tor status)" in
    disabled|starting|healthy|unavailable) pass "features.tor.status is one of the four contract words" ;;
    *) fail "features.tor.status is not one of the four contract words" ;;
esac
# Bootstrap needs outbound network. REQUIRE_OVERLAY=1 makes a missing network a failure instead of a SKIP.
for _ in $(seq 1 "${TOR_WAIT:-300}"); do [ "$(overlay tor status)" = "healthy" ] && break; sleep 1; done
if [ "$(overlay tor status)" = "healthy" ]; then
    if [[ "$(overlay tor hostname)" =~ ^[a-z2-7]{56}\.onion$ ]]; then pass "tor hostname is a v3 onion address"; else fail "tor hostname is not a v3 onion address"; fi
    check "features.tor.running is true" test "$(overlay tor running)" = "true"
    check "checks.tor is ok" test "$(healthz | jq -r '.checks.tor')" = "ok"
    check "onion hostname file persisted" test -s "${DATA_ROOT}/tor/site/hostname"
    for d in "${CONF_ROOT}/tor" "${DATA_ROOT}/tor" "${DATA_ROOT}/tor/site"; do
        check "$d is mode 700" test "$(stat -c %a "$d")" = "700"
    done
elif [ "${REQUIRE_OVERLAY:-0}" = "1" ]; then
    fail "Tor did not become healthy within ${TOR_WAIT:-300}s"
else
    echo "SKIP: Tor did not bootstrap within ${TOR_WAIT:-300}s (no outbound network?). The contract is still checked." >&2
    case "$(overlay tor status)" in
        starting) check "starting maps to checks.tor ok" test "$(healthz | jq -r '.checks.tor')" = "ok" ;;
        unavailable) check "unavailable maps to checks.tor degraded" test "$(healthz | jq -r '.checks.tor')" = "degraded" ;;
        *) fail "Tor is neither starting nor unavailable while not healthy" ;;
    esac
fi
if healthz | grep -Eq '/(etc|var|home|config|data)/'; then fail "health response leaks a filesystem path"; else pass "health response carries no filesystem path"; fi

echo "=== [$INIT_MODE] Tor missing binary (must be disabled, never an error) ==="
TOR_BINARIES=()
for tor_candidate in "$(command -v tor)" /bin/tor /usr/bin/tor /usr/local/bin/tor /sbin/tor /usr/sbin/tor /usr/local/sbin/tor; do
    if [ -e "$tor_candidate" ]; then
        tor_hidden="${tor_candidate}.codex-hidden.${BASHPID}"
        mv "$tor_candidate" "$tor_hidden"
        TOR_BINARIES+=("$tor_candidate|$tor_hidden")
    fi
done
${PROJECT_NAME} --service restart
wait_for 60 healthz_up
check "enabled is false without the binary" test "$(overlay tor enabled)" = "false"
check "running is false" test "$(overlay tor running)" = "false"
check "status is disabled" test "$(overlay tor status)" = "disabled"
check "hostname is empty" test -z "$(overlay tor hostname)"
check "checks.tor is omitted" test "$(healthz | jq '(.checks | has("tor"))')" = "false"
for tor_pair in "${TOR_BINARIES[@]}"; do
    tor_original=${tor_pair%%|*}
    tor_hidden=${tor_pair#*|}
    mv "$tor_hidden" "$tor_original"
done
${PROJECT_NAME} --service restart
wait_for 60 healthz_up

echo "=== [$INIT_MODE] I2P (off by default in a system container, i2pd is installed) ==="
check "i2pd binary is installed" command -v i2pd
check "server.yml is 0600 after start" test "$(stat -c %a "${CONF_ROOT}/server.yml")" = "600"
check "features.i2p.enabled is false by default in a system container" test "$(overlay i2p enabled)" = "false"
check "status is disabled by default" test "$(overlay i2p status)" = "disabled"
check "checks.i2p is omitted by default" test "$(healthz | jq '(.checks | has("i2p"))')" = "false"

echo "=== [$INIT_MODE] I2P enabled by a drop-in (opt-in, i2pd is installed) ==="
mkdir -p "${CONF_ROOT}/yaml.d"
printf 'server:\n  i2p:\n    enabled: true\n' > "${CONF_ROOT}/yaml.d/50-i2p.yml"
chown "${INTERNAL_NAME}:${INTERNAL_NAME}" "${CONF_ROOT}/yaml.d" "${CONF_ROOT}/yaml.d/50-i2p.yml"
chmod 0700 "${CONF_ROOT}/yaml.d"
chmod 0600 "${CONF_ROOT}/yaml.d/50-i2p.yml"
${PROJECT_NAME} --service restart
wait_for 60 healthz_up
check "features.i2p.enabled is true after opting in" test "$(overlay i2p enabled)" = "true"
check "features.i2p.provider is i2pd" test "$(overlay i2p provider)" = "i2pd"
case "$(overlay i2p status)" in
    starting|healthy|unavailable) pass "features.i2p.status is a contract word for an enabled network" ;;
    *) fail "features.i2p.status is not valid for an enabled network" ;;
esac
for _ in $(seq 1 "${I2P_WAIT:-600}"); do [ "$(overlay i2p status)" = "healthy" ] && break; sleep 1; done
if [ "$(overlay i2p status)" = "healthy" ]; then
    if [[ "$(overlay i2p hostname)" =~ ^[a-z2-7]{52}\.b32\.i2p$ ]]; then pass "i2p hostname is a .b32.i2p address"; else fail "i2p hostname is not a .b32.i2p address"; fi
    check "features.i2p.running is true" test "$(overlay i2p running)" = "true"
    check "checks.i2p is ok" test "$(healthz | jq -r '.checks.i2p')" = "ok"
    check "destination key persisted" sh -c "find '${DATA_ROOT}/i2p/site' -type f -size +0 | grep . >/dev/null"
elif [ "${REQUIRE_OVERLAY:-0}" = "1" ]; then
    fail "I2P did not become healthy within ${I2P_WAIT:-600}s"
else
    echo "SKIP: I2P did not build tunnels within ${I2P_WAIT:-600}s (no outbound network?). The contract is still checked." >&2
fi
if healthz | grep -Eq '/(etc|var|home|config|data)/'; then fail "health response leaks a filesystem path"; else pass "health response carries no filesystem path"; fi

echo "=== [$INIT_MODE] I2P missing provider (enabled by the drop-in, no i2pd: disabled, never an error) ==="
I2PD_BIN=$(command -v i2pd)
mv "$I2PD_BIN" "${I2PD_BIN}.hidden"
${PROJECT_NAME} --service restart
wait_for 60 healthz_up
check "enabled is false without a provider" test "$(overlay i2p enabled)" = "false"
check "status is disabled" test "$(overlay i2p status)" = "disabled"
check "provider is none" test "$(overlay i2p provider)" = "none"
check "checks.i2p is omitted" test "$(healthz | jq '(.checks | has("i2p"))')" = "false"
mv "${I2PD_BIN}.hidden" "$I2PD_BIN"
rm -f "${CONF_ROOT}/yaml.d/50-i2p.yml"
${PROJECT_NAME} --service restart
wait_for 60 healthz_up

[ "$FAILURES" -eq 0 ] || { echo "$FAILURES check(s) failed" >&2; exit 1; }
echo "=== [$INIT_MODE] Main tests passed ==="
REMOTE_MAIN_EOF
)

REMOTE_AFTER=$(cat <<'REMOTE_AFTER_EOF'
echo "=== [$INIT_MODE] Boot persistence (container was restarted) ==="
check "service still enabled after reboot" svc_enabled
check "service came back after reboot" wait_for 120 svc_active
check "health endpoint answers after reboot" wait_for 120 healthz_up

echo "=== [$INIT_MODE] Service disable (keeps the service file) ==="
${PROJECT_NAME} --service --disable
check_not "service not enabled after --disable" svc_enabled
check "service not active after --disable" wait_for 30 svc_stopped
check "service file kept after --disable" test -f "$UNIT_FILE"

echo "=== [$INIT_MODE] Service re-install ==="
${PROJECT_NAME} --service --install
check "service enabled again" svc_enabled
check "service active again" wait_for 30 svc_active
check "health endpoint answers again" wait_for 60 healthz_up

echo "=== [$INIT_MODE] Service uninstall (confirmation prompt answered with y) ==="
printf 'y\n' | ${PROJECT_NAME} --service --uninstall
check_not "service file removed" test -e "$UNIT_FILE"
check_not "service not enabled" svc_enabled
check "service not active" wait_for 30 svc_stopped
check_not "data directory removed" test -d "/var/lib/${INTERNAL_ORG}/${INTERNAL_NAME}"

[ "$FAILURES" -eq 0 ] || { echo "$FAILURES check(s) failed" >&2; exit 1; }
echo "=== [$INIT_MODE] All tests passed ==="
REMOTE_AFTER_EOF
)

# Every exec step has a ceiling: iexec SECONDS CONTAINER COMMAND...
iexec() {
    local secs="$1" container="$2"
    shift 2
    timeout "$secs" incus exec "$container" -- "$@"
}

# Run a script inside the container with the init mode and project names
# Every script fragment is its own argument: printf puts a newline after each one, because $(cat <<EOF) strips the trailing newline of a heredoc
remote() {
    local container="$1" init="$2"
    shift 2
    printf '%s\n' "$@" | timeout "$INCUS_RUN_TIMEOUT" incus exec "$container" -- env INIT_MODE="$init" PROJECT_NAME="$PROJECT_NAME" PROJECT_ORG="$PROJECT_ORG" API_VERSION="$API_VERSION" \
        INTERNAL_NAME="$INTERNAL_NAME" INTERNAL_ORG="$INTERNAL_ORG" REQUIRE_OVERLAY="${REQUIRE_OVERLAY:-0}" \
        CONFIG_DIR="/etc/${INTERNAL_ORG}/${INTERNAL_NAME}" DATA_DIR="/var/lib/${INTERNAL_ORG}/${INTERNAL_NAME}" \
        DATABASE_DIR="/var/lib/${INTERNAL_ORG}/${INTERNAL_NAME}/db" LOG_DIR="/var/log/${INTERNAL_ORG}/${INTERNAL_NAME}" \
        BACKUP_DIR="/mnt/Backups/${INTERNAL_ORG}/${INTERNAL_NAME}" \
        TOR_WAIT="${TOR_WAIT:-300}" I2P_WAIT="${I2P_WAIT:-600}" bash -s
}

# Wait until the container accepts commands, its init system finished booting and the network is up
wait_boot() {
    local container="$1" init="$2" state boot_attempt=1
    while [ "$boot_attempt" -le 60 ]; do
        iexec "$INCUS_OP_TIMEOUT" "$container" true 2>/dev/null && break
        sleep 1
        boot_attempt=$((boot_attempt + 1))
    done
    if [ "$init" = "systemd" ]; then
        # "degraded" is normal in a container; only "starting" means boot is unfinished
        local systemd_attempt=1
        while [ "$systemd_attempt" -le 90 ]; do
            state=$(iexec "$INCUS_OP_TIMEOUT" "$container" systemctl is-system-running 2>/dev/null || true)
            [ -n "$state" ] && [ "$state" != "starting" ] && break
            sleep 1
            systemd_attempt=$((systemd_attempt + 1))
        done
    else
        local openrc_attempt=1
        while [ "$openrc_attempt" -le 60 ]; do
            iexec "$INCUS_OP_TIMEOUT" "$container" test -d /run/openrc 2>/dev/null && break
            sleep 1
            openrc_attempt=$((openrc_attempt + 1))
        done
    fi
    local route_attempt=1
    while [ "$route_attempt" -le 60 ]; do
        iexec "$INCUS_OP_TIMEOUT" "$container" sh -c 'ip route | grep "^default" >/dev/null' 2>/dev/null && break
        sleep 1
        route_attempt=$((route_attempt + 1))
    done
}

run_mode() {
    local init="$1" image container
    if [ "$init" = "systemd" ]; then image="$INCUS_IMAGE_SYSTEMD"; else image="$INCUS_IMAGE_OPENRC"; fi
    container="${CONTAINER_PREFIX}-${init}"
    CONTAINERS+=("$container")

    echo "=== [$init] Launching Incus container ($image) ==="
    incus launch "$image" "$container" -c limits.cpu="$INCUS_CPUS" -c limits.memory="$INCUS_MEM" -c limits.cpu.priority="$INCUS_CPU_PRIORITY"
    wait_boot "$container" "$init"

    echo "=== [$init] Installing test tools, tor and i2pd ==="
    if [ "$init" = "systemd" ]; then
        iexec "$INCUS_INSTALL_TIMEOUT" "$container" bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq file tor i2pd' >/dev/null
        # The distro tor/i2pd services are NOT what is tested: the server runs its own dedicated, isolated instances (PART 31)
        iexec "$INCUS_OP_TIMEOUT" "$container" systemctl disable --now tor.service tor@default.service i2pd.service 2>/dev/null || true
    else
        iexec "$INCUS_INSTALL_TIMEOUT" "$container" sh -c 'apk add --no-cache bash curl jq file tor i2pd tzdata ca-certificates' >/dev/null
        iexec "$INCUS_OP_TIMEOUT" "$container" sh -c 'rc-service tor stop; rc-service i2pd stop; rc-update del tor; rc-update del i2pd' 2>/dev/null || true
    fi

    echo "=== [$init] Copying binaries to container ==="
    incus file push "${BIN_DIR}/${PROJECT_NAME}" "$container/usr/local/bin/"
    iexec "$INCUS_OP_TIMEOUT" "$container" chmod +x "/usr/local/bin/${PROJECT_NAME}"
    if [ -f "${BIN_DIR}/${PROJECT_NAME}-cli" ]; then
        incus file push "${BIN_DIR}/${PROJECT_NAME}-cli" "$container/usr/local/bin/"
        iexec "$INCUS_OP_TIMEOUT" "$container" chmod +x "/usr/local/bin/${PROJECT_NAME}-cli"
    fi

    echo "=== [$init] Running tests in Incus ==="
    remote "$container" "$init" "$REMOTE_LIB" "$REMOTE_MAIN"

    echo "=== [$init] Restarting the container (boot persistence) ==="
    incus restart "$container"
    wait_boot "$container" "$init"
    remote "$container" "$init" "$REMOTE_LIB" "$REMOTE_AFTER"
}

# One container per init system, run one after the other (never in parallel)
run_mode_list() {
    local init
    for init in $MODES; do
        run_mode "$init"
    done
}
run_mode_list

echo "Incus tests completed successfully ($MODES)"
