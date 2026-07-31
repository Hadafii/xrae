#!/usr/bin/env bash
#
# X-Rae installer.
#
# X-Rae has zero npm dependencies, so there is no `npm install`, no build step
# and no lockfile to audit. Installation is: copy files, make a user, install a
# systemd unit. That is the whole thing.
#
# Everything below is idempotent - running it twice is safe and will not
# overwrite your config.

set -euo pipefail

NODE_MAJOR="${NODE_MAJOR:-22}"
APP_DIR="${APP_DIR:-/opt/xrae}"
CONF_DIR="${CONF_DIR:-/etc/xrae}"
STATE_DIR="${STATE_DIR:-/var/lib/xrae}"
SERVICE_USER="${SERVICE_USER:-xrae}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PANEL_URL=""
NODE_TOKEN=""
PTERO_URL=""
PTERO_KEY=""
PTERO_NODE_ID=""
VOLUMES_PATH=""
NODE_BIN=""

die()  { printf '\n  error: %s\n\n' "$*" >&2; exit 1; }
step() { printf '  ==> %s\n' "$*"; }

WINGS_CONFIG="${WINGS_CONFIG:-/etc/pterodactyl/config.yml}"

# Wings already knows where the volumes are; asking the operator to retype it is
# how you end up scanning a directory that does not exist and reporting a clean
# node forever. Only the one scalar is read here; the richer detection (node id,
# panel URL) happens in `xrae provision`, where it can be tested.
read_wings_volumes_path() {
  [[ -r "$WINGS_CONFIG" ]] || return 0
  awk '
    /^[^[:space:]#]/ { in_system = ($0 ~ /^system[[:space:]]*:/) }
    in_system && /^[[:space:]]+data[[:space:]]*:/ {
      sub(/^[[:space:]]+data[[:space:]]*:[[:space:]]*/, "")
      gsub(/^["'"'"']|["'"'"']$/, "")
      print; exit
    }
  ' "$WINGS_CONFIG"
}

usage() {
  cat <<'USAGE'
  Usage: install.sh --panel URL --token TOKEN [--ptero-key KEY]

    --panel URL          X-Rae control panel, e.g. https://xrae.raehost.com
    --token TOKEN        node token issued by that panel (shown once)
    --ptero-key KEY      Pterodactyl application key (ptla_...)
    --ptero-url URL      Pterodactyl panel; read from Wings if omitted
    --node-id N          Pterodactyl node id; resolved from Wings if omitted
    --volumes-path PATH  read from Wings if omitted
    -h, --help           this text

  With --panel and --token the install is non-interactive end to end: it reads
  Wings' own config for the volumes path, resolves this machine's node id,
  verifies the token against the panel, writes both config files, installs the
  unit and starts it. This is the form the panel prints when you add a node.

  Without them the install stops after copying files and you finish by hand
  with `xrae init`.
USAGE
}

# Flags are parsed before the root check, so --help never needs sudo.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel) PANEL_URL="${2:-}"; shift 2 ;;
    --token) NODE_TOKEN="${2:-}"; shift 2 ;;
    --ptero-url) PTERO_URL="${2:-}"; shift 2 ;;
    --ptero-key) PTERO_KEY="${2:-}"; shift 2 ;;
    --node-id) PTERO_NODE_ID="${2:-}"; shift 2 ;;
    --volumes-path) VOLUMES_PATH="${2:-}"; shift 2 ;;
    --panel=*) PANEL_URL="${1#*=}"; shift ;;
    --token=*) NODE_TOKEN="${1#*=}"; shift ;;
    --ptero-url=*) PTERO_URL="${1#*=}"; shift ;;
    --ptero-key=*) PTERO_KEY="${1#*=}"; shift ;;
    --node-id=*) PTERO_NODE_ID="${1#*=}"; shift ;;
    --volumes-path=*) VOLUMES_PATH="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

# Half-configured reporting is worse than none: the node would look installed
# and simply never appear in the panel. Refuse instead of half-doing it.
[[ -n "$PANEL_URL" && -z "$NODE_TOKEN" ]] && die "--panel was given without --token"
[[ -n "$NODE_TOKEN" && -z "$PANEL_URL" ]] && die "--token was given without --panel"

printf '\n  X-Rae installer\n  ───────────────\n\n'

[[ $EUID -eq 0 ]] || die "run this with sudo (the service itself runs unprivileged)"
[[ -f "$SOURCE_DIR/bin/xrae" && -f "$SOURCE_DIR/xrae.env.example" ]] \
  || die "run this from inside the xrae directory"

# ---------------------------------------------------------------------------
# 0. Migrate a legacy "x-rae" install to the unified "xrae" naming
# ---------------------------------------------------------------------------
# Older versions used /opt/x-rae, /etc/x-rae, /var/lib/x-rae and x-rae.service.
# Everything is "xrae" now. This preserves your config, credentials and score
# history by moving them across, and retires the old unit. Idempotent: once
# migrated it does nothing.
if [[ -f /etc/systemd/system/x-rae.service ]]; then
  step "retiring legacy x-rae.service"
  systemctl stop x-rae.service 2>/dev/null || true
  systemctl disable x-rae.service 2>/dev/null || true
  rm -f /etc/systemd/system/x-rae.service
  systemctl daemon-reload
fi
if [[ -d /etc/x-rae && ! -e /etc/xrae ]]; then
  step "moving /etc/x-rae -> /etc/xrae"
  mv /etc/x-rae /etc/xrae
fi
if [[ -d /var/lib/x-rae && ! -e /var/lib/xrae ]]; then
  step "moving /var/lib/x-rae -> /var/lib/xrae"
  mv /var/lib/x-rae /var/lib/xrae
fi
if [[ -d /opt/x-rae ]]; then
  rm -rf /opt/x-rae
fi
# Repoint any old paths pinned inside the config/env so the stricter unit
# (StateDirectory=xrae, ReadWritePaths=/var/lib/xrae) can still write state.
for f in /etc/xrae/config.json /etc/xrae/xrae.env; do
  [[ -f "$f" ]] && sed -i 's#/var/lib/x-rae#/var/lib/xrae#g; s#/etc/x-rae#/etc/xrae#g' "$f"
done

# ---------------------------------------------------------------------------
# 1. Node.js
# ---------------------------------------------------------------------------
# We pin a MAJOR version rather than installing "latest". A surprise Node major
# upgrade on a production node is not something a security agent should cause.
if command -v node >/dev/null 2>&1 && [[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ]]; then
  step "Node.js $(node -v) already installed"
  NODE_BIN="$(command -v node)"
else
  step "installing Node.js ${NODE_MAJOR}.x"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg

  setup_script="$(mktemp)"
  trap 'rm -f "$setup_script"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o "$setup_script"
  # Never pipe a download straight into a root shell without looking at it.
  grep -q 'nodesource' "$setup_script" || die "the downloaded setup script does not look right; aborting"
  bash "$setup_script"
  apt-get install -y -qq nodejs
  NODE_BIN="$(command -v node)"
fi

# The unit used to hardcode /usr/bin/node. A node with nvm, snap or
# /usr/local/bin/node passed the version check above and then failed 203/EXEC in
# a restart loop, so the installer reported success on a node that never ran.
[[ -n "${NODE_BIN:-}" ]] || die "node is on PATH for this shell but could not be resolved"

# ---------------------------------------------------------------------------
# 2. Unprivileged service user
# ---------------------------------------------------------------------------
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  step "user $SERVICE_USER already exists"
else
  step "creating system user $SERVICE_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ---------------------------------------------------------------------------
# 3. Files
# ---------------------------------------------------------------------------
step "installing to $APP_DIR"
mkdir -p "$APP_DIR" "$CONF_DIR" "$STATE_DIR"
cp -r "$SOURCE_DIR/src" "$SOURCE_DIR/bin" "$SOURCE_DIR/package.json" "$APP_DIR/"
for doc in README.md ARCHITECTURE.md; do
  [[ -f "$SOURCE_DIR/$doc" ]] && cp "$SOURCE_DIR/$doc" "$APP_DIR/"
done

chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"
chmod +x "$APP_DIR/bin/xrae"

chown "$SERVICE_USER":"$SERVICE_USER" "$STATE_DIR"
chmod 750 "$STATE_DIR"

# A convenience wrapper so `xrae` works from anywhere.
cat > /usr/local/bin/xrae <<EOF
#!/bin/sh
exec $NODE_BIN $APP_DIR/bin/xrae "\$@"
EOF
chmod 755 /usr/local/bin/xrae
step "installed the xrae command"

# ---------------------------------------------------------------------------
# 5. Secrets file
# ---------------------------------------------------------------------------
# Copied from xrae.env.example rather than written inline here, so there is one
# source of truth. Duplicated content drifts.
if [[ -f "$CONF_DIR/xrae.env" ]]; then
  step "keeping existing $CONF_DIR/xrae.env"
else
  step "creating $CONF_DIR/xrae.env from the example"
  cp "$SOURCE_DIR/xrae.env.example" "$CONF_DIR/xrae.env"
fi

# Readable by the service user, writable only by root.
chown root:"$SERVICE_USER" "$CONF_DIR/xrae.env"
chmod 640 "$CONF_DIR/xrae.env"

# Keep the example on disk too, as reference documentation.
install -m 0644 "$SOURCE_DIR/xrae.env.example" "$APP_DIR/xrae.env.example"

# ---------------------------------------------------------------------------
# 6. systemd
# ---------------------------------------------------------------------------
# The old SonarX printed the `pm2 startup` command without running it, so the
# agent silently vanished on the next reboot while operators believed it was
# still watching. This actually enables the unit.
step "installing systemd unit"

# The unit ships with placeholder paths and is rendered here, because both of the
# values it needs are machine-specific:
#
#   node       hardcoding /usr/bin/node failed 203/EXEC on any node using nvm,
#              snap or /usr/local/bin.
#   volumes    ReadOnlyPaths with a path that does not exist is FATAL to systemd
#              (226/NAMESPACE), so a node whose Wings data lives elsewhere never
#              started at all. It is also prefixed with "-" now, which makes a
#              missing path non-fatal rather than a silent install failure.
VOLUMES_PATH="$(read_wings_volumes_path)"
[[ -n "$VOLUMES_PATH" ]] || VOLUMES_PATH="/var/lib/pterodactyl/volumes"

sed \
  -e "s|@NODE_BIN@|$NODE_BIN|g" \
  -e "s|@VOLUMES_PATH@|$VOLUMES_PATH|g" \
  "$SOURCE_DIR/systemd/xrae.service" > /etc/systemd/system/xrae.service
chmod 0644 /etc/systemd/system/xrae.service
systemctl daemon-reload
systemctl enable xrae.service >/dev/null 2>&1

# ---------------------------------------------------------------------------
# 7. Panel reporting (only when --panel and --token were given)
# ---------------------------------------------------------------------------
if [[ -n "$PANEL_URL" ]]; then
  step "provisioning against $PANEL_URL"

  # Everything the node needs is derived here, not asked for: `xrae provision`
  # reads Wings' own config for the volumes path and resolves this machine's
  # numeric Pterodactyl node id from its uuid. It also verifies the token before
  # writing anything, so a typo fails now rather than as silence in the panel.
  provision_args=(provision --config "$CONF_DIR/config.json" --panel "$PANEL_URL" --token "$NODE_TOKEN")
  [[ -n "$PTERO_URL"      ]] && provision_args+=(--ptero-url "$PTERO_URL")
  [[ -n "$PTERO_KEY"      ]] && provision_args+=(--ptero-key "$PTERO_KEY")
  [[ -n "$PTERO_NODE_ID"  ]] && provision_args+=(--node-id "$PTERO_NODE_ID")
  [[ -n "$VOLUMES_PATH"   ]] && provision_args+=(--volumes-path "$VOLUMES_PATH")

  set +e
  "$NODE_BIN" "$APP_DIR/bin/xrae" "${provision_args[@]}"
  provision_status=$?
  set -e

  chown root:"$SERVICE_USER" "$CONF_DIR/xrae.env" 2>/dev/null || true
  chmod 640 "$CONF_DIR/xrae.env" 2>/dev/null || true

  # 3 means "configured, but no Pterodactyl key yet". Starting then would give a
  # node that authenticates to the panel and fails every scan, which is the state
  # that used to look like a healthy install.
  if [[ $provision_status -eq 3 ]]; then
    printf '
  ──────────────────────────────────────────────────────────────────
  Configured, but NOT started: the Pterodactyl application key is missing.

  Add it, then start:

       sudo nano %s/xrae.env      # XRAE_PANEL_APP_KEY=ptla_...
       sudo systemctl start xrae
  ──────────────────────────────────────────────────────────────────

' "$CONF_DIR"
    exit 0
  fi

  [[ $provision_status -eq 0 ]] || die "provisioning failed; nothing was started"

  step "starting xrae"
  systemctl restart xrae.service

  # Give the unit a moment to either come up or die, then say which it was. The
  # old script printed "the service is running" without ever checking.
  sleep 2
  if systemctl is-active --quiet xrae.service; then
    printf '
  ──────────────────────────────────────────────────────────────────
  Done. This node is reporting to %s.

  It checks in immediately on startup, so it should already be visible
  in the panel. Watch it work:

       journalctl -u xrae -f

  It is in "observe" mode and will not touch a single server.
  ──────────────────────────────────────────────────────────────────

' "$PANEL_URL"
    exit 0
  fi

  printf '
  ──────────────────────────────────────────────────────────────────
  The service was installed and configured but is NOT running.

       systemctl status xrae
       journalctl -u xrae -n 50 --no-pager
  ──────────────────────────────────────────────────────────────────

'
  exit 1
fi

# An upgrade is `git pull && sudo ./install.sh`. Without this the new files were
# copied and the OLD process kept running, so operators believed they had
# upgraded while the previous modules stayed loaded. try-restart is a no-op when
# the unit is not running, which is what makes it safe on a first install.
if [[ -f "$CONF_DIR/config.json" ]] && systemctl is-enabled --quiet xrae.service 2>/dev/null; then
  step "restarting xrae to pick up the new files"
  systemctl try-restart xrae.service || true
fi

printf '
  ──────────────────────────────────────────────────────────────────
  Installed. Three commands to finish:

    1. sudo xrae init --config %s/config.json
    2. sudo nano %s/xrae.env        # paste your keys
    3. sudo -u %s xrae doctor --config %s/config.json

  Then see what it would do, without it doing anything:

       sudo -u %s xrae scan --config %s/config.json --dry-run --verbose

  When you are happy:

       sudo systemctl start xrae
       journalctl -u xrae -f

  It starts in "observe" mode and will not touch a single server until
  you deliberately change that. Leave it there for a few weeks.
  ──────────────────────────────────────────────────────────────────

' "$CONF_DIR" "$CONF_DIR" "$SERVICE_USER" "$CONF_DIR" "$SERVICE_USER" "$CONF_DIR"
