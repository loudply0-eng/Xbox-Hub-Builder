# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository contains only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, SSH credentials, or user data into this repository.
- Never upload source archives, checkout directories, plaintext app packages, private logs, signing material, or private keys as workflow artifacts.
- The only application package artifact permitted here is the authenticated encrypted `.xhubenc` container, encrypted to the owner's public package-encryption key.

## Current workflows

- `private-source-check.yml` — verifies the read-only private-source connection, compiles the offline package decryptor and manifest signer, and runs six disposable-key regression tests (five decryptor tests plus one signer test).
- `windows-build-check.yml` — Windows x64 restore/publish, exact two-file ZIP validation, offline manifest-signer positive/negative tests, encrypted-package round-trip and tamper tests, and updater replacement/rollback tests.
- `xcl-runtime-windows-build.yml` — builds the separately licensed XCL runtime from its pinned upstream source.
- `update-host-smoke-check.yml` — weekly and manually dispatchable external DNS, HTTP redirect, TLS-chain, and stable-manifest endpoint check.

The source checkout uses the read-only `SOURCE_REPO_DEPLOY_KEY` Actions secret and sets `persist-credentials: false`. The private source is checked out only on the trusted `main` branch. The Windows workflow publishes into runner-temporary storage, validates the ZIP, tests the offline signer and package encryption with disposable keys, then encrypts the actual package for the owner's public recipient key. It uploads only the encrypted container with a three-day retention period. The production release-signing key and package-decryption private key are never used by CI.

The Windows build workflow runs on manual dispatch, when the trusted build-trigger marker changes on `main`, and through a lightweight 15-minute source-revision poll. The poll uses an Ubuntu runner to inspect the private source `main` commit and compare it with immutable `xboxhub-source-<sha>` tags in this public builder. A Windows build starts only for a previously unseen revision (or an explicit manual/marker trigger), checks out the exact detected commit, and records a tag only after successful validation. No Windows runner is used when the scheduled poll finds no new source revision. This automates build-and-encrypted-artifact handoff only; it does not sign or publish a production stable release. It is a build-validation and encrypted-package handoff workflow; it is **not** a production release-signing or deployment workflow.

## Latest Xbox Hub build — 2026-11-25

<https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45527708556>

- Result: **success** (workflow run 45; all three jobs succeeded).
- Source: private `loudply0-eng/Xbox-Hub-for-PC` `main`, commit `2d5dd4564597f9bb343c1da88a39c316de306e59`.
- App version: `0.1.11`.
- Windows x64 package: `XboxHub-0.1.11-win-x64.zip`.
- Plaintext package size: `91,686,495` bytes.
- Plaintext package SHA-256: `3B13BFA85CB8B3C170ECE3934E40F02948BEF1B7AEBA82082ED7460A03596817`.
- Uploaded artifact: `xboxhub-encrypted-offline-package` (encrypted `.xhubenc` only; artifact ID `14982993087`).
- Artifact expiry: **2026-11-28 01:43:53 UTC**.

The successful run restored and published the app and standalone updater, validated the exact two-file ZIP, passed offline signature-helper positive/negative checks with throwaway keys, verified package encryption/decryption round-trip and tamper rejection, and passed updater replacement, rollback, and path-validation tests. The upload contains only the authenticated encrypted package. The plaintext ZIP, private source, production signing key, package-decryption key, and passphrases were not uploaded.

This is a **0.1.11 release candidate build**, not a published stable release. Manual Windows acceptance testing of this exact candidate and the complete live-feed update test remain outstanding. The package digest above is for the plaintext ZIP created on the isolated runner, not the encrypted GitHub artifact archive.

## Automatic update service status

The 0.1.11 app checks the signed stable feed at startup and automatically downloads and installs a newer release only after the embedded RSA-3072 public key verifies the manifest and the package passes exact byte-count and SHA-256 checks. A 12-hour background check does not restart the app mid-session; an update found then is installed on the next launch. The separate updater retains backup and rollback protection.

The dedicated HTTPS host is provisioned. The latest recorded external health check passed on 2026-11-24:

<https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45320477641>

That check confirmed public DNS, the exact HTTP-to-HTTPS redirect, and TLS certificate validation. The stable endpoint `/stable/manifest.json` returned **404** in that check, because the signed stable manifest and package had not yet been published. It has not been independently rechecked since then.

Therefore the updater code is implemented but **live automatic updates are not yet available**. The production release-signing and package-decryption keys remain offline; OCI Vault signing/decryption, GitHub-to-OCI workload identity, and controlled host deployment are not configured. Do not place production private keys or passphrases in GitHub Actions or on the Oracle VM.

## Secret handling

- The public source-checkout key is a read-only deploy key registered on `loudply0-eng/Xbox-Hub-for-PC`; its private half is stored as `SOURCE_REPO_DEPLOY_KEY` in this builder's Actions secrets.
- Never enable write access for that deploy key.
- Never put the production RSA release-signing private key, its passphrase, the package-decryption private key, the Oracle TLS key, server credentials, or a long-lived server SSH key in this public repository, GitHub Actions secrets, logs, or artifacts.
- The production release-signing private key remains offline. CI must use disposable keys only for tests.
- Keep workflow changes restricted to trusted maintainers. A workflow executing on `main` can access the private-source checkout key, so review every change to secret-bearing workflows before merging or dispatching it.

## Dependency maintenance

`.github/dependabot.yml` configures weekly checks for GitHub Actions references. Review Dependabot pull requests and retain full-SHA pinning when updating Actions.

## Future release deployment

Do not add production signing secrets or long-lived server credentials to this public repository. Production publication must accept only an offline-signed manifest and the exact package bytes it describes. Any future GitHub-to-Oracle deployment integration must use a narrowly scoped, short-lived authentication design and independently verify the signed manifest, package digest, release sequence, and exact output paths on the host.
