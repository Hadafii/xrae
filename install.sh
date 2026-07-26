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
APP_DIR="${APP_DIR:-/opt/x-rae}"
CONF_DIR="${CONF_DIR:-/etc/x-rae}"
STATE_DIR="${STATE_DIR:-/var/lib/x-rae}"
SERVICE_USER="${SERVICE_USER:-xrae}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die()  { printf '\n  error: %s\n\n' "$*" >&2; exit 1; }
step() { printf '  ==> %s\n' "$*"; }

printf '\n  X-Rae installer\n  ───────────────\n\n'

[[ $EUID -eq 0 ]] || die "run this with sudo (the service itself runs unprivileged)"
[[ -f "$SOURCE_DIR/bin/xrae" ]] || die "run this from inside the x-rae directory"

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
# 4. Secrets file
# ---------------------------------------------------------------------------
if [[ ! -f "$CONF_DIR/xrae.env" ]]; then
  cat > "$CONF_DIR/xrae.env" <<'EOF'
# Credentials for X-Rae. Uncomment and fill in.
# Keeping them here rather than in config.json means they never appear in a
# file you might paste into a chat when asking for help.
# XRAE_PANEL_APP_KEY=ptla_...
# XRAE_PANEL_CLIENT_KEY=ptlc_...
# XRAE_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
EOF
fi
chown root:"$SERVICE_USER" "$CONF_DIR/xrae.env"
chmod 640 "$CONF_DIR/xrae.env"

# ---------------------------------------------------------------------------
# 5. systemd
# ---------------------------------------------------------------------------
# The old SonarX printed the `pm2 startup` command without running it, so the
# agent silently vanished on the next reboot while operators believed it was
# still watching. This actually enables the unit.
step "installing systemd unit"
install -m 0644 "$SOURCE_DIR/systemd/x-rae.service" /etc/systemd/system/x-rae.service
systemctl daemon-reload
systemctl enable x-rae.service >/dev/null 2>&1

printf '
  ──────────────────────────────────────────────────────────────────
  Installed. Three commands to finish:

    1. sudo xrae init --config %s/config.json
    2. sudo nano %s/xrae.env        # paste your keys
    3. sudo -u %s xrae doctor --config %s/config.json

  Then see what it would do, without it doing anything:

       sudo -u %s xrae scan --config %s/config.json --dry-run --verbose

  When you are happy:

       sudo systemctl start x-rae
       journalctl -u x-rae -f

  It starts in "observe" mode and will not touch a single server until
  you deliberately change that. Leave it there for a few weeks.
  ──────────────────────────────────────────────────────────────────

' "$CONF_DIR" "$CONF_DIR" "$SERVICE_USER" "$CONF_DIR" "$SERVICE_USER" "$CONF_DIR"
