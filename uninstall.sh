#!/usr/bin/env bash
#
# X-Rae uninstaller.
#
# Removal used to mean remembering five paths, a systemd unit and a system user.
# Undocumented removal steps are how dead agents linger on nodes for months.
#
# Config and score history are KEPT by default, because the common reason to run
# this is reinstalling, and losing the detection history would reset every
# server's score to zero and hide anything mid-escalation. Pass --purge when you
# really mean it.

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/xrae}"
CONF_DIR="${CONF_DIR:-/etc/xrae}"
STATE_DIR="${STATE_DIR:-/var/lib/xrae}"
SERVICE_USER="${SERVICE_USER:-xrae}"

PURGE=0

die()  { printf '\n  error: %s\n\n' "$*" >&2; exit 1; }
step() { printf '  ==> %s\n' "$*"; }

usage() {
  cat <<'USAGE'
  Usage: uninstall.sh [--purge]

    --purge     also delete /etc/xrae (credentials) and /var/lib/xrae (score
                history), and remove the xrae system user
    -h, --help  this text

  Without --purge the service is stopped and the program removed, but your
  config and history stay put so a reinstall picks up where it left off.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this with sudo"

printf '\n  X-Rae uninstaller\n  ─────────────────\n\n'

if systemctl list-unit-files xrae.service >/dev/null 2>&1; then
  step "stopping and disabling xrae.service"
  systemctl disable --now xrae.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/xrae.service
  systemctl daemon-reload
  systemctl reset-failed xrae.service >/dev/null 2>&1 || true
fi

step "removing $APP_DIR and the xrae command"
rm -rf "$APP_DIR"
rm -f /usr/local/bin/xrae

if [[ $PURGE -eq 1 ]]; then
  step "purging $CONF_DIR and $STATE_DIR"
  rm -rf "$CONF_DIR" "$STATE_DIR"

  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    step "removing user $SERVICE_USER"
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  fi

  printf '\n  Removed completely.\n\n'
  exit 0
fi

printf '
  Removed. Kept, so a reinstall resumes cleanly:

     %s     credentials and settings
     %s     detection history

  Delete those too with:  sudo ./uninstall.sh --purge

' "$CONF_DIR" "$STATE_DIR"
