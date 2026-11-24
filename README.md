# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository must contain only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, or user data into this repository.
- Do not upload source archives, checkout directories, private logs, or signing material as workflow artifacts.

## Current workflows

- `private-source-check.yml` — manual-only check that verifies the read-only connection to the private source repository.
- `windows-build-check.yml` — Windows x64 restore/publish, two-file ZIP layout validation, updater transaction tests, and a PowerShell parser-only check of the offline release-key helper (the helper is never executed and no key is generated). It runs on manual dispatch and whenever the trusted build-trigger marker changes on `main`.

Both workflows run only from `main`, use the dedicated read-only SSH deploy key stored as `SOURCE_REPO_DEPLOY_KEY`, and set `persist-credentials: false`. The Windows workflow checks out the current private `main`, publishes the app and updater to runner-temporary storage, validates the ZIP, and runs transaction tests; it never uploads source or build artifacts. For each assistant-made source update, the build-trigger marker is advanced to start this check without requiring a server command from the user. It is validation, not a signed release pipeline.

The private app currently contains an early WPF shell. Preview `0.1.7-preview.1` passed Windows x64 publish, two-file package validation, updater transaction tests, and PowerShell parser checks for both offline signing helpers on 2026-11-24 (run [45316482619](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45316482619)). The temporary ZIP measured 91,672,141 bytes with SHA-256 `1DAA657E074EFD461D051AB3614BA7A3D14E8DC9025EE62B46A57E4711BA0D68`. No artifacts were uploaded. The signed feed and public key are still unconfigured, so no live automatic update can be downloaded yet; runtime integrations and Authenticode signing are also outstanding.

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
