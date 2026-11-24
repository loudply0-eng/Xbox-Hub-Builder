# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository must contain only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, or user data into this repository.
- Never upload source archives, checkout directories, plaintext app packages, private logs, signing material, or private keys as workflow artifacts. Only the authenticated encrypted package container may be uploaded after the owner's public encryption key is configured.

## Current workflows

- `private-source-check.yml` — manual-only check that verifies the read-only connection to the private source repository.
- `windows-build-check.yml` — Windows x64 restore/publish, exact two-file ZIP validation, strict offline manifest signer positive/negative tests, encrypted package round-trip/tamper tests, and updater transaction tests. It runs on manual dispatch and whenever the trusted build-trigger marker changes on `main`.

Both workflows run only from `main`, use the dedicated read-only SSH deploy key stored as `SOURCE_REPO_DEPLOY_KEY`, and set `persist-credentials: false`. The Windows workflow checks out the current private `main`, publishes the app and updater to runner-temporary storage, validates the ZIP, tests offline signing and package encryption using throwaway keys, and runs transaction tests. It never uploads private source or a plaintext app package. Once the owner's package-encryption public key is configured in the private source, it may upload only an AES-256-GCM encrypted package container as a short-lived artifact (three-day retention); the matching private decryption key remains on the owner's trusted PC. Until that public key is configured, no artifact is uploaded. For each assistant-made source update, the build-trigger marker is advanced to start this check without requiring a server command from the user. It is validation and encrypted package handoff, not a signed release pipeline.

The private app currently contains an early WPF shell. Preview `0.1.7-preview.1` passed Windows x64 publish, two-file ZIP validation, updater transaction tests, and parser checks for both offline signing helpers. The latest run [45317687480](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45317687480) also exercised the manifest signer end-to-end with an ephemeral CI-only RSA-3072 key and confirmed it rejects bad package hashes, cross-host URLs, and mismatched key IDs. OpenSSL returned `Verified OK`. Temporary ZIP: 91,672,122 bytes; SHA-256 `0A3D1549B5CCCB3144BDEB4093FB2F5549B5C09495F34F14A3D88C615D3A2268`. No artifacts were uploaded. The signed feed and public key remain unconfigured, so no live automatic update can be downloaded yet.

## Secret handling

- The public key is registered as a read-only deploy key on `loudply0-eng/Xbox-Hub-for-PC`.
- The private half is stored only as this repository's Actions secret `SOURCE_REPO_DEPLOY_KEY`.
- Never enable write access for that deploy key.
- Never paste, print, commit, or upload the private key.

Treat every workflow modification on `main` as security-sensitive. Anyone able to change and run a secret-bearing workflow on the trusted branch could attempt to expose the private source or its credential. Limit write access to trusted maintainers and review workflow changes before dispatching them.

## Dependency maintenance

`.github/dependabot.yml` configures weekly checks for GitHub Actions references. Review Dependabot pull requests and retain full-SHA pinning when updating Actions.

## Future release pipeline

Do not add release signing secrets to this public repository. A production release pipeline must publish only intended binaries and signed update metadata after a separate signing and update trust design has been reviewed.
