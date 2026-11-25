# Xbox Hub Oracle release worker

This service polls the public builder's encrypted candidate releases, decrypts the package through OCI Vault HSM, signs the stable manifest through OCI Vault HSM, and atomically publishes to the existing HTTPS feed.

## Security model

- Uses OCI Instance Principals on the Oracle VM. No OCI API key, OCI config file, GitHub PAT, SSH key, or application private key is stored on the VM.
- The two existing RSA-3072 private keys must be imported as HSM-protected keys into OCI Vault. The worker receives only key OCIDs and key-version OCIDs.
- Only an authenticated .xhubenc package is downloaded. The worker validates RSA-OAEP-SHA256 unwrap, AES-256-GCM authentication, plaintext SHA-256, the exact two executable ZIP entries, and ZIP CRC.
- The manifest uses SHA-256 with RSA PKCS#1 v1.5 through Vault. It is independently verified against the public key already embedded in the app.
- The package is written first and the manifest is atomically replaced last. A failed update leaves the previous manifest unchanged.
- Preview releases are ignored. The first Stable publication is gated by default; later higher stable sequences publish automatically.

## One-time OCI setup

1. Use a Vault in the same region as the Oracle VM. Import two existing RSA 3072-bit keys in HSM protection mode: the package-decryption key matching the app's package public key, and the signing key matching the public key embedded in the app. Import requires OCI's RSA_OAEP_AES_SHA256 key-material wrapping procedure. Never put private key material in GitHub, the VM, Actions secrets, or this worker.
2. Create a Dynamic Group for only this VM. Matching rule: instance.id = '<ORACLE_COMPUTE_INSTANCE_OCID>'.
3. In the keys' compartment, grant this Dynamic Group use access to only the two key OCIDs with target.key.id conditions. Example statements:
   - Allow dynamic-group XboxHubReleaseWorker to use keys in compartment XboxHubVaultCompartment where target.key.id = '<PACKAGE_KEY_OCID>'
   - Allow dynamic-group XboxHubReleaseWorker to use keys in compartment XboxHubVaultCompartment where target.key.id = '<SIGNING_KEY_OCID>'
   The use keys permission includes KEY_DECRYPT and KEY_SIGN. HSM-protected keys cannot be exported.
4. Record the vault KMS crypto endpoint and both key OCIDs plus their active key-version OCIDs.
5. Ensure the VM can reach OCI's instance metadata service and the Vault crypto endpoint. OCI manages and rotates the Instance Principal certificates.

## One-time VM installation

On Oracle Linux, install Python 3, pip, and the nginx group. Place this directory at /opt/xboxhub-release-worker, create a Python virtual environment there, and install requirements.txt.

Create /etc/xboxhub-release-worker.env as root, mode 0640, readable by opc. Set:
- XHUB_KMS_CRYPTO_ENDPOINT=https://<vault-crypto-endpoint>
- XHUB_PACKAGE_KEY_OCID=<package-key-ocid>
- XHUB_PACKAGE_KEY_VERSION_OCID=<package-key-version-ocid>
- XHUB_SIGNING_KEY_OCID=<signing-key-ocid>
- XHUB_SIGNING_KEY_VERSION_OCID=<signing-key-version-ocid>
- XHUB_RELEASE_DIRECTORY=/var/www/xbox-hub-updates/stable
- XHUB_GITHUB_REPOSITORY=loudply0-eng/Xbox-Hub-Builder
- XHUB_ALLOW_INITIAL_STABLE=false

Install the supplied service and timer unit files under /etc/systemd/system. Ensure opc can write to the stable webroot and nginx can read the files. Enable the timer; it checks every 15 minutes.

## First Stable acceptance

When the stable manifest is absent, publication remains disabled until XHUB_ALLOW_INITIAL_STABLE is set to true after the owner accepts the first release, checks that both imported key versions are correct, and confirms the webroot. Once a valid signed manifest exists, all later higher stable releases are processed automatically.

## Tests

Tests use ephemeral RSA keys only and do not call OCI. Run python3 -m unittest -v from this directory.


## Compatibility with the current stable feed

The worker reads and verifies the existing signed Stable manifest in legacy-compatible mode so the previously deployed sequence (including the older 0.1.10 feed) remains usable. New candidates and every newly signed manifest must use the current deterministic semantic-version sequence. Legacy compatibility applies only to the already-published feed manifest; it does not relax candidate validation.


## One-time Oracle Linux installation

After both OCI HSM keys have been prepared and the VM Dynamic Group policy is in place, install the worker once from the Oracle SSH terminal:

~~~bash
curl -fsSL https://raw.githubusercontent.com/loudply0-eng/Xbox-Hub-Builder/main/oracle-release-worker/install.sh -o install.sh
sudo bash install.sh
~~~

The installer downloads worker files from a pinned public-builder commit, installs Python dependencies, asks once for the five non-secret Vault endpoint/key OCID values, writes a root-owned `0640` environment file, installs the hardened systemd service and timer, and runs the first poll. It preserves an existing environment file. After installation, the timer polls every 15 minutes without Windows PowerShell or a GitHub token.

The installer does not import private keys or create OCI IAM policies. Those owner/admin actions must be completed in OCI Console first. Initial Stable publication remains gated if no signed manifest already exists.
