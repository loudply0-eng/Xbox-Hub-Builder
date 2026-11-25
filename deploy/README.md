# Xbox Hub release agent — Oracle Linux

This directory contains the release publisher for the dedicated Oracle Linux update host.

## Security design

- GitHub Actions builds the private application source in the public builder workflow.
- Each successful build uploads two separate artifacts: the authenticated encrypted .xhubenc package and a small non-secret release-metadata JSON file.
- The Oracle VM agent accepts only successful main-branch workflow runs with the immutable xboxhub-source-<private-source-sha> success tag.
- It prefers the permanent prerelease handoff `xboxhub-candidate-<source-sha>` and reads its non-secret metadata asset first. It falls back to the 90-day Actions metadata/package artifacts only when the permanent candidate release is not yet available. It skips downloading the large encrypted package when the candidate is already published.
- For a new stable version, OCI Vault decrypts the RSA-wrapped AES package key and signs the exact stable manifest payload.
- The Oracle VM uses its Instance Principal. No GitHub secret, long-lived OCI API key, PEM private key, or signing passphrase is stored on the VM or in GitHub.
- The app verifies the signed manifest, exact byte count, and SHA-256 before its startup updater installs a new release.
The agent also keeps a root-owned-by-service, mode-0600 publication ledger at `/var/lib/xboxhub-release-agent/state.json`. The last successful release identity is checked independently of the public manifest, so deleting or losing `manifest.json` cannot silently reset the publisher's stable version floor. A malformed state file fails closed and requires operator recovery; it is not silently overwritten.

**Publication is disabled by default.** Keep XBOXHUB_RELEASE_AUTO_PUBLISH_ENABLED=false until the exact first candidate has been manually accepted on Windows and the OCI key self-test succeeds.

## 1. Create the two Vault HSM keys

Use the existing encrypted Xbox Hub private-key files on the trusted Windows computer:

- Package decryption key: %LOCALAPPDATA%\XboxHub\ReleaseSigning\xbox-hub-package-decrypt-private.pem
- Stable manifest signing key: %LOCALAPPDATA%\XboxHub\ReleaseSigning\xbox-hub-release-private.pem

Do not upload either private PEM or either passphrase to GitHub, the Oracle VM, or this repository.

In the OCI Console, use the Vault that will hold these keys. For each key:

1. Start **Create Key** and choose **Protection Mode: HSM**, **Algorithm: RSA**, and **Length: 3072**.
2. Select **Import External Key** and the **RSA_OAEP_AES_SHA256** wrapping algorithm.
3. Copy the Vault's **public RSA wrapping key** from the import-key form and save it as a PEM file on the trusted Windows computer.
4. Prepare the matching import file using the local Python helper below, then upload only its .bin output into the OCI import form.
5. Record the new key OCID and its key-version OCID.

OCI requires RSA private key material to be wrapped as PKCS#8 using the Vault's RSA wrapping key and RSA_OAEP_AES_SHA256. The helper does this locally and validates each key against the public key ID embedded in Xbox Hub. It makes no network requests.

### Prepare the wrapped import files on Windows

Install Python 3 if it is not already available. Open **Command Prompt** (not PowerShell) and run:

~~~bat
py -3 -m pip install --upgrade cryptography
mkdir "%TEMP%\XboxHub-key-import"
curl.exe -fL "https://raw.githubusercontent.com/loudply0-eng/Xbox-Hub-Builder/main/deploy/prepare_oci_rsa_import.py" -o "%TEMP%\XboxHub-key-import\prepare_oci_rsa_import.py"
~~~

Save the Vault's public wrapping key as:

%TEMP%\XboxHub-key-import\vault-rsa-wrapping-public.pem

Create the package-decryption import file:

~~~bat
py -3 "%TEMP%\XboxHub-key-import\prepare_oci_rsa_import.py" --role package-decryption --private-key "%LOCALAPPDATA%\XboxHub\ReleaseSigning\xbox-hub-package-decrypt-private.pem" --vault-wrapping-public-key "%TEMP%\XboxHub-key-import\vault-rsa-wrapping-public.pem" --output "%USERPROFILE%\Downloads\xboxhub-package-decrypt-oci-import.bin"
~~~

Create the separate release-signing import file:

~~~bat
py -3 "%TEMP%\XboxHub-key-import\prepare_oci_rsa_import.py" --role release-signing --private-key "%LOCALAPPDATA%\XboxHub\ReleaseSigning\xbox-hub-release-private.pem" --vault-wrapping-public-key "%TEMP%\XboxHub-key-import\vault-rsa-wrapping-public.pem" --output "%USERPROFILE%\Downloads\xboxhub-release-signing-oci-import.bin"
~~~

Each run prompts for the encrypted PEM passphrase without echoing it. The helper verifies the RSA-3072 public fingerprint and refuses to overwrite an existing output. Upload the two .bin files directly to the matching OCI Vault **Import External Key** forms. Delete those temporary wrapped files after OCI confirms import; keep the original encrypted PEM backups offline.

The package-decryption key ID must be xboxhub-package-rsa3072-b845262d34ea685b. The release-signing key ID must be xboxhub-rsa3072-9986345089cc1513. Do not rotate either imported key or change its imported key version without a coordinated app/builder key-rotation release.

## 2. Grant the exact Oracle VM access to those two keys

Find the OCID of the Oracle Linux instance hosting updates.mahmoudaljuorany.store.

Create a Dynamic Group named XboxHubReleaseAgent with this exact match rule:

~~~text
ALL {instance.id = '<ORACLE_VM_INSTANCE_OCID>'}
~~~

Create a policy in the compartment that contains the two Vault keys. Grant use of only those key IDs:

~~~text
Allow dynamic-group XboxHubReleaseAgent to use keys in compartment <KEY_COMPARTMENT_NAME> where target.key.id = '<PACKAGE_DECRYPTION_KEY_OCID>'
Allow dynamic-group XboxHubReleaseAgent to use keys in compartment <KEY_COMPARTMENT_NAME> where target.key.id = '<RELEASE_SIGNING_KEY_OCID>'
~~~

The policy is deliberately limited to the two specified keys. Do not grant manage keys, manage vaults, or tenancy-wide permissions to this agent.

Copy the Vault **Cryptographic Endpoint** (not the Management Endpoint) and the two key OCIDs and key-version OCIDs. The agent uses the cryptographic endpoint for RSA-OAEP decryption and RSA/SHA-256 signing.

## 3. Install the agent on Oracle Linux

From an authenticated SSH session to the update host, run:

~~~bash
curl -fL "https://raw.githubusercontent.com/loudply0-eng/Xbox-Hub-Builder/main/deploy/install-xboxhub-release-agent.sh" -o /tmp/install-xboxhub-release-agent.sh
sudo bash /tmp/install-xboxhub-release-agent.sh
~~~

The installer creates a restricted xboxhub-release service account, a shared Nginx group for published files, a Python virtual environment, and hardened systemd service/timer units. It writes the settings template to /etc/xboxhub-release-agent.env and stops without enabling publication.

Edit /etc/xboxhub-release-agent.env and set:

~~~ini
XBOXHUB_KMS_CRYPTO_ENDPOINT=https://<VAULT_CRYPTO_ENDPOINT>
XBOXHUB_PACKAGE_KEY_OCID=<PACKAGE_DECRYPTION_KEY_OCID>
XBOXHUB_PACKAGE_KEY_VERSION_OCID=<PACKAGE_DECRYPTION_KEY_VERSION_OCID>
XBOXHUB_SIGNING_KEY_OCID=<RELEASE_SIGNING_KEY_OCID>
XBOXHUB_SIGNING_KEY_VERSION_OCID=<RELEASE_SIGNING_KEY_VERSION_OCID>
XBOXHUB_STABLE_DIR=/var/www/xbox-hub-updates/stable
XBOXHUB_STATE_FILE=/var/lib/xboxhub-release-agent/state.json
XBOXHUB_RELEASE_AUTO_PUBLISH_ENABLED=false
~~~

Use the exact OCIDs copied from OCI. The environment file contains identifiers and an endpoint only; it must never contain PEM files, passphrases, API signing keys, GitHub tokens, or SSH credentials.

Run the installer a second time after saving the values:

~~~bash
sudo bash /tmp/install-xboxhub-release-agent.sh
~~~

Before it enables the 10-minute timer, the installer starts xboxhub-release-agent-check.service. That check uses the VM's Instance Principal to:

- decrypt a fresh random AES-256 test key using the imported package key, then verify that the recovered bytes match;
- sign a fresh challenge with the imported release-signing key, then verify it against the public key embedded in the app.

The self-test does not download an app package, alter the feed, or publish anything. It must pass before the timer is enabled.

Inspect the result with:

~~~bash
sudo systemctl status xboxhub-release-agent-check.service
sudo journalctl -u xboxhub-release-agent-check.service -n 100 --no-pager
sudo systemctl status xboxhub-release-agent.timer
~~~

## 4. Accept the first release, then enable automatic publication

Keep XBOXHUB_RELEASE_AUTO_PUBLISH_ENABLED=false while manually decrypting and testing the exact first candidate on Windows. Confirm the app launches, the user library/settings are preserved, and the separate updater can replace/rollback files in a clean test profile.

Only after that acceptance, change the flag in /etc/xboxhub-release-agent.env to:

~~~ini
XBOXHUB_RELEASE_AUTO_PUBLISH_ENABLED=true
~~~

Then start one publication run:

~~~bash
sudo systemctl start xboxhub-release-agent.service
sudo journalctl -u xboxhub-release-agent.service -n 100 --no-pager
~~~

After the first successful publication, open the public builder repository Settings → Secrets and variables → Actions → Variables and create or set `XBOXHUB_REQUIRE_STABLE_FEED` to `true`. This switches the external weekly health check from allowing the pre-release HTTP 404 to requiring HTTP 200 for `/stable/manifest.json`. The variable is not a secret and does not grant permissions. The 10-minute systemd timer automatically checks for later stable build candidates. A newer stable version is accepted only after:

- the public builder run completed successfully;
- its permanent candidate prerelease (or fallback Actions artifacts) has GitHub SHA-256 digests matching the downloaded asset bytes;
- its exact private-source SHA has a matching immutable success tag;
- metadata is valid and matches the exact decrypted package size and SHA-256;
- the encrypted container authenticates with AES-256-GCM using the configured Vault package key;
- the Vault signature verifies locally against the RSA public key embedded in Xbox Hub;
- the version sequence is greater than the already published sequence;
- the exact public HTTPS package and manifest bytes return HTTP 200 without redirects.

Preview versions are never published to the stable feed. Existing versioned package paths are immutable. The manifest is replaced last as the publication commit point.

## 5. Operations and recovery

~~~bash
sudo systemctl status xboxhub-release-agent.timer
sudo systemctl start xboxhub-release-agent.service
sudo journalctl -u xboxhub-release-agent.service -n 100 --no-pager
sudo systemctl stop xboxhub-release-agent.timer
~~~

If OCI permissions or key fingerprints fail, the agent stops without changing the public manifest. Correct the Dynamic Group, two key-scoped policy statements, endpoint, or OCID/version values; rerun xboxhub-release-agent-check.service before enabling the timer again.

The previous stable manifest remains the last visible release if a new candidate cannot be decrypted, signed, or verified. A package file is immutable once written. The service does not write source code or release private keys to the public repository or the Oracle VM.

## Relevant Oracle references

- [Import RSA key material into an HSM-protected Vault key](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/importing_asymmetric_keys_topic_to_import_the_key_material_as_a_new_external_key.htm)
- [Get the Vault's public RSA wrapping key](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/importingkeys_topic-To_get_the_public_RSA_wrapping_key.htm)
- [Wrap RSA private key material using RSA-OAEP with AES](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/importing_asymmetric_keys_topic_to_apply_rsa_oaep_with_aes_to_wrap_the_key_material.htm)
- [Use an HSM-backed Vault key to sign data](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/usingkeys_topic-To_sign_data_by_using_your_Vault_master_encryption_key.htm)
- [Use Instance Principals and Dynamic Groups](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingdynamicgroups.htm)
