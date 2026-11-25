#!/usr/bin/env bash
set -Eeuo pipefail

REPO="loudply0-eng/Xbox-Hub-Builder"
REF="@${XBOXHUB_AGENT_REF:-main}"
BASE_URL="https://raw.githubusercontent.com/@${REPO}/@${REF}/deploy"
APP_DIR="/opt/xboxhub-release-agent"
STATE_DIR="/var/lib/xboxhub-release-agent"
STABLE_DIR="/var/www/xbox-hub-updates/stable"
ENV_FILE="/etc/xboxhub-release-agent.env"
AGENT_USER="xboxhub-release"
AGENT_GROUP="xboxhub-updates"

if [[ "@${EUID}" -ne 0 ]]; then
  echo "Run this installer once with sudo/root on the Oracle Linux update host." >&2
  exit 1
fi

for command in curl python3 systemctl getent useradd groupadd usermod; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is missing: $command" >&2
    exit 1
  }
done

if ! getent group "$AGENT_GROUP" >/dev/null; then
  groupadd --system "$AGENT_GROUP"
fi

if ! getent passwd "$AGENT_USER" >/dev/null; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /sbin/nologin --gid "$AGENT_GROUP" "$AGENT_USER"
else
  usermod --append --groups "$AGENT_GROUP" "$AGENT_USER"
fi

NGINX_USER="$(awk '$1 == "user" { gsub(";", "", $2); print $2; exit }' /etc/nginx/nginx.conf 2>/dev/null || true)"
NGINX_USER="@${NGINX_USER:-nginx}"
if ! getent passwd "$NGINX_USER" >/dev/null; then
  echo "Could not identify the Nginx worker account ($NGINX_USER)." >&2
  exit 1
fi
usermod --append --groups "$AGENT_GROUP" "$NGINX_USER"

install -d -o root -g root -m 0755 "$APP_DIR"
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0750 "$STATE_DIR"
install -d -o root -g "$AGENT_GROUP" -m 2775 "$STABLE_DIR"

fetch_file() {
  local remote="$1"
  local destination="$2"
  curl --fail --silent --show-error --location --max-time 60 \
    "$BASE_URL/$remote" --output "$destination.new"
  install -o root -g root -m 0644 "$destination.new" "$destination"
  rm -f "$destination.new"
}

fetch_file "xboxhub_release_agent.py" "$APP_DIR/xboxhub_release_agent.py"
fetch_file "requirements.txt" "$APP_DIR/requirements.txt"
fetch_file "xboxhub-release-agent.service" "/etc/systemd/system/xboxhub-release-agent.service"
fetch_file "xboxhub-release-agent.timer" "/etc/systemd/system/xboxhub-release-agent.timer"

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
"$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"
chmod 0755 "$APP_DIR" "$APP_DIR/venv/bin/python"
chmod 0644 "$APP_DIR/xboxhub_release_agent.py" "$APP_DIR/requirements.txt"

if [[ ! -f "$ENV_FILE" ]]; then
  fetch_file "xboxhub-release-agent.env.example" "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
  echo
  echo "Installer prepared the release agent but did not enable the timer."
  echo "Edit $ENV_FILE and replace every REPLACE_WITH value with the OCI Vault endpoint and exact key/key-version OCIDs."
  echo "Do not put PEM files, private keys, passphrases, or OCI API secrets in this file."
  exit 0
fi

if grep -q "REPLACE_WITH" "$ENV_FILE"; then
  echo "The OCI settings file still contains REPLACE_WITH placeholders: $ENV_FILE" >&2
  echo "Fill in the Vault crypto endpoint, package-decryption key OCID/version, and signing key OCID/version." >&2
  exit 1
fi

chown root:root "$ENV_FILE"
chmod 0600 "$ENV_FILE"

systemctl daemon-reload
systemctl restart nginx
systemctl enable --now xboxhub-release-agent.timer
systemctl start xboxhub-release-agent.service

echo
echo "Xbox Hub release agent installed."
echo "Timer: systemctl status xboxhub-release-agent.timer"
echo "Last run: systemctl status xboxhub-release-agent.service"
echo "Logs: journalctl -u xboxhub-release-agent.service -n 100 --no-pager"
