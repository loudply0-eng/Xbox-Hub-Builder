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

## Latest Xbox Hub build — 2026-11-24

<https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45441847709>

- Result: **success** (workflow run 39).
- Source: private `loudply0-eng/Xbox-Hub-for-PC` `main`, commit `f94198cb1677be27f6d0dff4572b1d82933f0c64`.
- App version: `0.1.9`.
- Windows x64 package: `XboxHub-0.1.9-win-x64.zip`.
- Plaintext package size, measured in the isolated runner: `91,686,171` bytes.
- Plaintext package SHA-256: `7C016619D8FB7C1ADD0834E9EFE367D5334819B1C40E02995D68D8BAF4821F26`.
- Uploaded artifact: `xboxhub-encrypted-offline-package` (encrypted `.xhubenc` only).
- Artifact expiry: **2026-11-27 16:52:04 UTC**.

The successful run published both self-contained executables, validated the exact two-file ZIP, passed positive and negative offline-signing tests with a throwaway CI key, verified package encryption/decryption byte-for-byte with a disposable test recipient, rejected a tampered ciphertext, and passed the updater replacement and rollback tests. No plaintext package, private source, production signing key, package-decryption key, or passphrase was uploaded.

The phone-side decryptor and its disposable-key tests passed separately in [private-source test run 45441847945](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45441847945): all five decryptor cases plus the manifest-signer test completed successfully (`Ran 6 tests`).

This is a **0.1.9 release candidate build**, not a published stable release. The encrypted artifact must be decrypted by the owner with the separate offline package-decryption key before the ZIP can be inspected and tested on Windows. The recorded hash and size above refer to the plaintext ZIP, not the outer GitHub artifact archive.

## Automatic update service status

The private app contains the signed-manifest verification, startup and 12-hour update checks, package size/SHA-256 validation, and a separate updater with rollback. The app now presents a verified update and waits for the user's explicit **Download and install update** action.

The dedicated HTTPS host is provisioned. The latest external health check passed on 2026-11-24:

<https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45320477641>

That check confirmed public DNS resolves to the configured Oracle IPv4, HTTP redirects to the same HTTPS hostname, and both curl and OpenSSL validate the public TLS certificate chain. The stable endpoint `/stable/manifest.json` returned **404**, which is currently expected because the signed stable manifest and package have not been deployed.

Therefore the update client is implemented but **live automatic updates are not yet available**. Before calling the service live, the owner must test the decrypted 0.1.9 package, sign the exact package metadata offline with the production RSA release key, deploy the ZIP and signed envelope to the dedicated HTTPS host, and complete a clean-Windows end-to-end update/restart/rollback test.

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
