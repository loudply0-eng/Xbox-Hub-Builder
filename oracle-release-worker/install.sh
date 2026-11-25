#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

readonly APP_DIR="/opt/xboxhub-release-worker"
readonly ENV_FILE="/etc/xboxhub-release-worker.env"
readonly RELEASE_DIR="/var/www/xbox-hub-updates/stable"
readonly SOURCE_REPOSITORY="loudply0-eng/Xbox-Hub-Builder"
readonly SOURCE_REVISION="545513e8e0eecc47e9ac75402cd980683217f18a"
readonly BASE_URL="https://raw.githubusercontent.com/${SOURCE_REPOSITORY}/${SOURCE_REVISION}/oracle-release-worker"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash install.sh"
[[ -x /usr/bin/dnf ]] || die "This installer targets Oracle Linux 9 / DNF."
id opc >/dev/null 2>&1 || die "The Oracle VM user 'opc' does not exist."

info "Installing Oracle Linux runtime prerequisites"
dnf install -y python3 python3-pip nginx curl ca-certificates
getent group nginx >/dev/null 2>&1 || die "nginx group not found."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "Downloading worker files from pinned public-builder revision"
for file in xboxhub_release_worker.py requirements.txt xboxhub-release-worker.service xboxhub-release-worker.timer; do
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "${BASE_URL}/${file}" --output "${tmp}/${file}"
    [[ -s "${tmp}/${file}" ]] || die "Downloaded file is empty: ${file}"
done

info "Installing worker into ${APP_DIR}"
install -d -o root -g root -m 0755 "$APP_DIR"
install -o root -g root -m 0644 "$tmp/xboxhub_release_worker.py" "$APP_DIR/xboxhub_release_worker.py"
install -o root -g root -m 0644 "$tmp/requirements.txt" "$APP_DIR/requirements.txt"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
"$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements.txt"
"$APP_DIR/venv/bin/python" -m py_compile "$APP_DIR/xboxhub_release_worker.py"

if [[ ! -s "$ENV_FILE" ]]; then
    [[ -t 0 ]] || die "Missing $ENV_FILE. Run interactively once or create the documented root-owned environment file."
    info "Enter the non-secret OCI Vault endpoint and key identifiers from OCI Console"
    read -r -p "Vault KMS crypto endpoint (https://...): " kms_endpoint
    read -r -p "Package RSA key OCID: " package_key_ocid
    read -r -p "Package RSA key-version OCID: " package_version_ocid
    read -r -p "Manifest signing RSA key OCID: " signing_key_ocid
    read -r -p "Manifest signing key-version OCID: " signing_version_ocid

    [[ "$kms_endpoint" =~ ^https://[A-Za-z0-9.-]+$ ]] || die "Vault endpoint must be a bare HTTPS endpoint."
    [[ "$package_key_ocid" =~ ^ocid1\.key\.[A-Za-z0-9._-]+$ ]] || die "Package key OCID format is invalid."
    [[ "$package_version_ocid" =~ ^ocid1\.keyversion\.[A-Za-z0-9._-]+$ ]] || die "Package key-version OCID format is invalid."
    [[ "$signing_key_ocid" =~ ^ocid1\.key\.[A-Za-z0-9._-]+$ ]] || die "Signing key OCID format is invalid."
    [[ "$signing_version_ocid" =~ ^ocid1\.keyversion\.[A-Za-z0-9._-]+$ ]] || die "Signing key-version OCID format is invalid."

    cat >"$tmp/worker.env" <<EOF
XHUB_KMS_CRYPTO_ENDPOINT=$kms_endpoint
XHUB_PACKAGE_KEY_OCID=$package_key_ocid
XHUB_PACKAGE_KEY_VERSION_OCID=$package_version_ocid
XHUB_SIGNING_KEY_OCID=$signing_key_ocid
XHUB_SIGNING_KEY_VERSION_OCID=$signing_version_ocid
XHUB_RELEASE_DIRECTORY=$RELEASE_DIR
XHUB_GITHUB_REPOSITORY=$SOURCE_REPOSITORY
XHUB_ALLOW_INITIAL_STABLE=false
EOF
    install -o root -g opc -m 0640 "$tmp/worker.env" "$ENV_FILE"
else
    info "Preserving existing $ENV_FILE"
    chown root:opc "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
fi

for variable in XHUB_KMS_CRYPTO_ENDPOINT XHUB_PACKAGE_KEY_OCID XHUB_PACKAGE_KEY_VERSION_OCID XHUB_SIGNING_KEY_OCID XHUB_SIGNING_KEY_VERSION_OCID; do
    grep -Eq "^$variable=.+$" "$ENV_FILE" || die "Missing $variable in $ENV_FILE."
done

info "Preparing existing HTTPS update directory"
install -d -o opc -g nginx -m 2750 "$RELEASE_DIR"
chown opc:nginx "$RELEASE_DIR"
chmod 2750 "$RELEASE_DIR"

info "Installing hardened systemd service and 15-minute timer"
install -o root -g root -m 0644 "$tmp/xboxhub-release-worker.service" /etc/systemd/system/xboxhub-release-worker.service
install -o root -g root -m 0644 "$tmp/xboxhub-release-worker.timer" /etc/systemd/system/xboxhub-release-worker.timer
systemctl daemon-reload
systemctl enable --now xboxhub-release-worker.timer

info "Running first authenticated poll"
systemctl start xboxhub-release-worker.service

printf '\nInstallation complete.\n'
printf 'Timer status: '
systemctl is-enabled xboxhub-release-worker.timer
printf 'Last worker result: '
systemctl show xboxhub-release-worker.service --property=Result --value
printf '\nRecent worker log:\n'
journalctl -u xboxhub-release-worker.service -n 25 --no-pager || true
printf '\nThe worker will poll every 15 minutes. It requires no Windows PowerShell or GitHub token.\n'
