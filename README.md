# Xbox Hub Builder

Public repository for reviewed build automation only. The authoritative application source remains private in [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC).

## Security boundary

- Never copy application source, private configuration, signing keys, certificates, access tokens, SSH credentials, or user data into this repository.
- Never upload source archives, checkout directories, plaintext app packages, private logs, signing material, or private keys as workflow artifacts.
- The application package artifact must be the authenticated encrypted .xhubenc container, encrypted to the owner's public package-encryption key.
- The separate release-metadata artifact is non-secret. It contains version, release notes, plaintext ZIP size/SHA-256, source commit SHA, and builder run identifiers only.
- Production release-signing and package-decryption private keys are never used by CI.

## Current workflows and release tooling

- private-source-check.yml — verifies the read-only private-source connection and tests offline helper tools with disposable keys.
- windows-build-check.yml — Windows x64 restore/publish, exact two-file ZIP validation, offline manifest-signer positive/negative tests, encrypted-package round-trip and tamper tests, metadata generation, and updater replacement/rollback tests.
- release-agent-tests.yml — compiles the Oracle release agent and local key-import helper, checks OCI SDK crypto request models, validates the Oracle Linux installer syntax, and runs the cryptographic/release-metadata regression suite. The suite now contains 21 tests. New regression coverage verifies stable-manifest rollback when HTTPS verification fails, removal of an unverified first manifest, revalidation of already-current package and manifest bytes, and protection against release downgrade using persistent publication state even if the manifest is missing or the state file is malformed. The additions are awaiting their next Actions result.
- xcl-runtime-windows-build.yml — builds the separately licensed XCL runtime from its pinned upstream source.
- update-host-smoke-check.yml — scheduled external DNS, same-host redirect, TLS-chain, signed stable-manifest, package URL, exact package size/SHA-256, and ZIP-layout/CRC checks. The currently published stable feed is required by default: HTTP 404 fails the health check. The workflow also verifies the manifest signature and exact package bytes, ZIP layout, and CRCs.
- deploy/xboxhub_release_agent.py — Oracle Linux release agent using the VM's OCI Instance Principal and two narrowly scoped Vault HSM keys.
- deploy/prepare_oci_rsa_import.py — local offline wrapper that prepares the owner's encrypted RSA private keys for OCI HSM import, without sending the PEM or passphrase anywhere.
- deploy/install-xboxhub-release-agent.sh and deploy/README.md — one-time Oracle Linux installation and OCI configuration instructions.

## Private-source build automation

The source checkout uses the read-only SOURCE_REPO_DEPLOY_KEY Actions secret and sets persist-credentials=false. The workflow definition and secret-bearing job run only from the trusted Builder main branch; private source refs are selected from a fixed allowlist. Pull-request branches cannot supply or execute the Builder workflow definition.

The public builder polls private Xbox Hub main every 15 minutes and compares it with immutable xboxhub-source-<sha> success tags. A Windows runner starts only for a new private-source revision (or an explicit manual trigger), checks out the exact detected SHA, validates the app and updater, and records a tag only after all build and handoff steps succeed. Scheduled runs always inspect private-source main. For controlled PR validation, workflow_dispatch offers the allowlisted refs main, feature/defer-updates-during-known-game-sessions, and fix/prevent-failed-update-retry-loop; the workflow resolves the selected ref to an exact commit SHA before building. A manually selected branch build creates only the encrypted prerelease handoff and does not publish the stable feed. No Windows runner is used when the scheduled poll finds no new private-source revision.

Every successful candidate build produces two separate short-lived Actions artifacts:
1. xboxhub-encrypted-offline-package — the encrypted .xhubenc app package only.
2. xboxhub-release-metadata — a small non-secret JSON sidecar.

Both Actions artifacts have a 90-day retention period. The build also publishes a permanent prerelease handoff at `xboxhub-candidate-<private-source-sha>`, containing exactly the encrypted package and metadata sidecar. The release handoff is **not** a stable update. The Oracle agent prefers these persistent candidate-release assets and falls back to the Actions artifacts when the permanent handoff is not yet available. Both paths verify GitHub's SHA-256 asset/archive digests, and the agent reads metadata first so it avoids downloading the large encrypted package when a version is already published.

The permanent-release upload step compares the exact local SHA-256 and size of both files with GitHub's asset metadata. If an existing candidate release contains stale assets from an earlier build of the same source SHA, it replaces the assets and verifies the resulting remote digests before marking the build successful.

## Latest validated application build

[Windows build run 45532434575](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45532434575) completed successfully as workflow run **53**. All four jobs passed: private-source detection, Windows build/package tests, encrypted permanent-candidate handoff, and successful-source marker creation.

- Private-source revision: `d5784af33a173f844a9a84fe362d18531df5ada7`.
- App version: `0.1.11`.
- Plaintext package size: **91,686,459 bytes**.
- Plaintext package SHA-256: `c299ddc3799956b700a010da9babbed8273a1ca20af36a0fa5989b003c7cb2af`.
- Encrypted container size: **91,687,343 bytes**.
- Encrypted container SHA-256: `89867cebf068928ba31bd5e13a7815e7a83d89260c6cc443ba803792eb7dbe3`.
- Release metadata sidecar size: **1,106 bytes**.
- Release metadata sidecar SHA-256: `1153a6caa84b5f5947baa8b8c9e7ca5bb3d358403d8fbcafb66a05527180b6fc`.

The permanent encrypted handoff is available at [Xbox Hub 0.1.11 candidate release](https://github.com/loudply0-eng/Xbox-Hub-Builder/releases/tag/xboxhub-candidate-d5784af33a173f844a9a84fe362d18531df5ada7). Its two asset digests were checked against the exact encrypted package and metadata emitted by build #53. The 90-day Actions artifact IDs are `14984624567` (encrypted package) and `14984549434` (metadata sidecar).

This is a **0.1.11 candidate handoff**, not a published stable release. The package remains encrypted; no plaintext ZIP or private source was uploaded. Manual Windows acceptance testing of this exact candidate and a complete live-feed update test are still required.

## Automatic update client

The 0.1.11 app checks the signed stable feed at startup and automatically downloads and installs a newer release only after the embedded RSA-3072 public key verifies the manifest and the package passes exact byte-count and SHA-256 checks. A 12-hour background check does not restart the app mid-session; an update found then is installed on the next launch. The separate updater retains backup and rollback protection.

The dedicated HTTPS host passed end-to-end verification in [health-check run 45542965810](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45542965810): DNS, exact HTTP-to-HTTPS redirect, TLS, RSA signature against the app's public key, and the 0.1.10 package's exact size/SHA-256, two-file ZIP layout, and CRCs. The currently verified stable feed is **0.1.10**, not 0.1.11. The 0.1.11 package from build #53 remains an encrypted candidate handoff pending Windows acceptance and controlled publication.

## OCI publication status

The Oracle release agent and one-time installation assets are prepared in `deploy/`. The design uses:

- a package-decryption RSA-3072 key imported into OCI Vault HSM;
- a separate release-signing RSA-3072 key imported into OCI Vault HSM;
- an exact-instance Dynamic Group and key-scoped IAM policies;
- the Oracle VM's Instance Principal for short-lived Vault access;
- a 10-minute systemd timer after installation;
- an independent OCI key self-test before the timer is enabled.

Automatic publication is **disabled by default** in `deploy/xboxhub-release-agent.env.example`. The agent does not publish the first candidate until the owner has manually accepted that exact Windows build and explicitly enables the setting. Once that initial acceptance is completed, later stable candidates can be signed and published automatically. Preview versions are never sent to the stable feed.

**The OCI resources and Oracle VM release-agent service have not yet been configured.** The Vault keys have not been imported, the Dynamic Group and IAM policies have not been created, and the installation script has not been run on the Oracle VM. The existing 0.1.10 feed is independently verified, but automatic publication of future candidates is not yet active. The repository tools can modify GitHub, but they do not provide an authenticated OCI Console or Oracle VM session. See [deploy/README.md](deploy/README.md) for the remaining one-time setup.

## Secret handling

- The public source-checkout key is a read-only deploy key registered on loudply0-eng/Xbox-Hub-for-PC; its private half is stored as SOURCE_REPO_DEPLOY_KEY in this builder's Actions secrets.
- Never enable write access for that deploy key.
- Never put production RSA private keys, key passphrases, OCI API credentials, server credentials, or SSH keys in either repository, GitHub Actions, logs, or artifacts.
- The Oracle agent uses only the VM Instance Principal and the two exact Vault key IDs. Nginx receives read-only group access to the published stable files; only the release-agent account can write them.
- Review all workflow changes on main because the Windows workflow uses the read-only private-source checkout key.

## Dependency maintenance

.dependabot.yml configures weekly checks for GitHub Actions references. Review dependency updates and retain full-SHA pinning when updating Actions.
