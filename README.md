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

The source checkout uses the read-only `SOURCE_REPO_DEPLOY_KEY` Actions secret and sets `persist-credentials: false`. The private source is checked out only on the trusted `main` branch. The Windows workflow publishes into runner-temporary storage, validates the ZIP, tests the offline signer and package encryption with disposable keys, then encrypts the actual package for the owner's public recipient key. It uploads the authenticated encrypted container and its non-secret release metadata as a short-lived Actions artifact, then publishes the same two files as a permanent GitHub prerelease after validating the metadata. The production release-signing key and package-decryption private key are never used by CI.

The Windows build workflow runs on manual dispatch, when the trusted build-trigger marker changes on `main`, and through a lightweight 15-minute source-revision poll. The poll uses an Ubuntu runner to inspect the private source `main` commit and compare it with immutable `xboxhub-source-<sha>` tags in this public builder. A Windows build starts only for a previously unseen revision (or an explicit manual/marker trigger), checks out the exact detected commit, and records a tag only after all successful handoff steps complete. No Windows runner is used when the scheduled poll finds no new source revision. After validation, the workflow publishes the authenticated encrypted `.xhubenc` package and non-secret release metadata as a GitHub prerelease uniquely keyed by the private-source SHA. This gives the Oracle release worker a durable public download without a long-lived GitHub credential. The prerelease is only an encrypted build handoff: it does not sign or publish a production stable update.

## Latest Xbox Hub build — 2026-11-25

<https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45529059625>

- Result: **success** (workflow run 46; all three jobs succeeded).
- Source: private `loudply0-eng/Xbox-Hub-for-PC` `main`, commit `d5784af33a173f844a9a84fe362d18531df5ada7`.
- App version: `0.1.11`.
- Windows x64 package: `XboxHub-0.1.11-win-x64.zip`.
- Plaintext package size: `91,686,459` bytes.
- Plaintext package SHA-256: `F08A8082164AA7DF52FCF3925E340975268C692C50423D4BD8608ECA32498E52`.
- Uploaded artifact: `xboxhub-encrypted-offline-package` (encrypted `.xhubenc` only; artifact ID `14983199517`).
- Artifact expiry: **2026-11-28 01:55:01 UTC**.

The successful run checked out the exact current private-source commit, restored and published the app and standalone updater, validated the exact two-file ZIP, passed offline signature-helper positive/negative checks with throwaway keys, verified package encryption/decryption round-trip and tamper rejection, and passed updater replacement, rollback, and path-validation tests. The upload contains only the authenticated encrypted package. The plaintext ZIP, private source, production signing key, package-decryption key, and passphrases were not uploaded.

This is a **0.1.11 candidate build**, not a published stable release. Manual Windows acceptance testing of this exact candidate and the complete live-feed update test remain outstanding. The plaintext digest above identifies the ZIP produced inside the isolated runner; it is not the checksum of the encrypted GitHub artifact archive.

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
