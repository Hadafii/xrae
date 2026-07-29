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

die()  { printf '\n  error: %s\n\n' "$*" >&2; exit 1; }
step() { printf '  ==> %s\n' "$*"; }

usage() {
  cat <<'USAGE'
  Usage: install.sh [--panel URL --token TOKEN]

    --panel URL     X-Rae control panel, e.g. https://xrae.raehost.com
    --token TOKEN   node token issued by that panel (shown once)
    -h, --help      this text

  With both flags the install is non-interactive: reporting is configured and
  the service is started for you. This is the form the panel prints when you
  add a node. Without them the install stops after copying files, exactly as
  before, and you finish by hand.
USAGE
}

# Flags are parsed before the root check, so --help never needs sudo.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel) PANEL_URL="${2:-}"; shift 2 ;;
    --token) NODE_TOKEN="${2:-}"; shift 2 ;;
    --panel=*) PANEL_URL="${1#*=}"; shift ;;
    --token=*) NODE_TOKEN="${1#*=}"; shift ;;
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
fi

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
exec /usr/bin/node $APP_DIR/bin/xrae "\$@"
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
install -m 0644 "$SOURCE_DIR/systemd/xrae.service" /etc/systemd/system/xrae.service
systemctl daemon-reload
systemctl enable xrae.service >/dev/null 2>&1

# ---------------------------------------------------------------------------
# 7. Panel reporting (only when --panel and --token were given)
# ---------------------------------------------------------------------------
if [[ -n "$PANEL_URL" ]]; then
  step "configuring reporting to $PANEL_URL"

  ENV_FILE="$CONF_DIR/xrae.env"
  touch "$ENV_FILE"

  # Replace in place if present, append if not, so re-running with a rotated
  # token updates rather than stacking duplicate lines (systemd takes the last
  # one, which makes duplicates a confusing way to be wrong).
  for pair in "XRAE_REPORTING_URL=$PANEL_URL" "XRAE_REPORTING_TOKEN=$NODE_TOKEN"; do
    key="${pair%%=*}"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
      sed -i "s|^${key}=.*|${pair}|" "$ENV_FILE"
    else
      printf '%s\n' "$pair" >> "$ENV_FILE"
    fi
  done

  chown root:"$SERVICE_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"

  if [[ -f "$CONF_DIR/config.json" ]]; then
    step "starting xrae"
    systemctl restart xrae.service
    printf '
  ──────────────────────────────────────────────────────────────────
  Reporting to %s is configured and the service is running.

  This node appears in the panel on its first heartbeat, usually within
  seconds. Watch it come up with:

       journalctl -u xrae -f
  ──────────────────────────────────────────────────────────────────

' "$PANEL_URL"
    exit 0
  fi

  printf '
  Reporting is configured, but there is no %s/config.json yet, so the
  service was not started. Finish with:

       sudo xrae init --config %s/config.json
       sudo systemctl start xrae

' "$CONF_DIR" "$CONF_DIR"
  exit 0
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
