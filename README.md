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
- release-agent-tests.yml — compiles the Oracle release agent and local key-import helper, checks OCI SDK crypto request models, validates the Oracle Linux installer syntax, and runs cryptographic regression tests.
- xcl-runtime-windows-build.yml — builds the separately licensed XCL runtime from its pinned upstream source.
- update-host-smoke-check.yml — scheduled external DNS, HTTP redirect, TLS-chain, and stable-manifest endpoint checks.
- deploy/xboxhub_release_agent.py — Oracle Linux release agent using the VM's OCI Instance Principal and two narrowly scoped Vault HSM keys.
- deploy/prepare_oci_rsa_import.py — local offline wrapper that prepares the owner's encrypted RSA private keys for OCI HSM import, without sending the PEM or passphrase anywhere.
- deploy/install-xboxhub-release-agent.sh and deploy/README.md — one-time Oracle Linux installation and OCI configuration instructions.

## Private-source build automation

The source checkout uses the read-only SOURCE_REPO_DEPLOY_KEY Actions secret and sets persist-credentials=false. The private source is checked out only on the trusted main branch.

The public builder polls private Xbox Hub main every 15 minutes and compares it with immutable xboxhub-source-<sha> success tags. A Windows runner starts only for a new private-source revision (or an explicit manual/marker trigger), checks out the exact detected SHA, validates the app and updater, and records a tag only after all build and handoff steps succeed. No Windows runner is used when the scheduled poll finds no new source revision.

The Windows workflow now uploads two separate short-lived artifacts:
1. xboxhub-encrypted-offline-package — the encrypted .xhubenc app package only.
2. xboxhub-release-metadata — a small non-secret JSON sidecar.

The plaintext ZIP and private source remain on the isolated Windows runner and are not uploaded. Both artifacts expire after three days. The Oracle release agent checks successful workflow runs and source-success tags, verifies GitHub's artifact archive digests, reads metadata first, and downloads the large encrypted package only when a newer stable candidate needs publication.

## Latest validated application build

[Windows build run 45529059625](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45529059625) completed successfully (workflow run 46; all three jobs succeeded).

- Private-source revision: d5784af33a173f844a9a84fe362d18531df5ada7.
- App version: 0.1.11.
- Plaintext package size: 91,686,459 bytes.
- Plaintext package SHA-256: F08A8082164AA7DF52FCF3925E340975268C692C50423D4BD8608ECA32498E52.
- Encrypted artifact ID: 14983199517; expired on 2026-11-28 01:55:01 UTC.

This earlier successful build predates the separate metadata artifact change; the next Windows build validates that updated handoff format. The 0.1.11 candidate is not a published stable release. Manual Windows acceptance testing of this exact candidate and a complete live-feed update test are still required.

## Automatic update client

The 0.1.11 app checks the signed stable feed at startup and automatically downloads and installs a newer release only after the embedded RSA-3072 public key verifies the manifest and the package passes exact byte-count and SHA-256 checks. A 12-hour background check does not restart the app mid-session; an update found then is installed on the next launch. The separate updater retains backup and rollback protection.

The dedicated HTTPS host has previously passed DNS, same-host HTTP-to-HTTPS redirect, and TLS validation in [health-check run 45320477641](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45320477641). That check returned HTTP 404 for /stable/manifest.json on 2026-11-24. The host has not been rechecked since that date.

## OCI publication status

The Oracle release agent and one-time installation assets are prepared in deploy/. The design uses:

- a package-decryption RSA-3072 key imported into OCI Vault HSM;
- a separate release-signing RSA-3072 key imported into OCI Vault HSM;
- an exact-instance Dynamic Group and key-scoped IAM policies;
- the Oracle VM's Instance Principal for short-lived Vault access;
- a 10-minute systemd timer after installation;
- an independent OCI key self-test before the timer is enabled.

Automatic publication is **disabled by default** in deploy/xboxhub-release-agent.env.example. The agent does not publish the first candidate until the owner has manually accepted that exact Windows build and explicitly enables the setting. Once that initial acceptance is completed, later stable candidates can be signed and published automatically. Preview versions are never sent to the stable feed.

**The OCI resources and Oracle VM service have not yet been configured.** The Vault keys have not been imported, the Dynamic Group and IAM policies have not been created, the installation script has not been run on the Oracle VM, and no stable manifest or package has been published. This repository connection can modify GitHub files and workflows, but it does not provide an authenticated OCI Console or Oracle VM session. See [deploy/README.md](deploy/README.md) for the remaining one-time setup.

## Secret handling

- The public source-checkout key is a read-only deploy key registered on loudply0-eng/Xbox-Hub-for-PC; its private half is stored as SOURCE_REPO_DEPLOY_KEY in this builder's Actions secrets.
- Never enable write access for that deploy key.
- Never put production RSA private keys, key passphrases, OCI API credentials, server credentials, or SSH keys in either repository, GitHub Actions, logs, or artifacts.
- The Oracle agent uses only the VM Instance Principal and the two exact Vault key IDs. Nginx receives read-only group access to the published stable files; only the release-agent account can write them.
- Review all workflow changes on main because the Windows workflow uses the read-only private-source checkout key.

## Dependency maintenance

.dependabot.yml configures weekly checks for GitHub Actions references. Review dependency updates and retain full-SHA pinning when updating Actions.
