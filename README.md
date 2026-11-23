# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository must contain only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, or user data into this repository.
- Do not upload source archives, checkout directories, private logs, or signing material as workflow artifacts.

## Current workflows

- `private-source-check.yml` — manual-only check that verifies the read-only connection to the private source repository.
- `windows-build-check.yml` — Windows build check for the private WPF application using the .NET 10 SDK. It runs on manual dispatch and whenever the trusted build-trigger marker changes on `main`.

Both workflows run only from `main`, use the dedicated read-only SSH deploy key stored as `SOURCE_REPO_DEPLOY_KEY`, and set `persist-credentials: false`. The Windows build workflow checks out the current private `main` source at run time, does not upload source or build artifacts, and is a compile check—not a signed release pipeline. For each assistant-made source update, the build-trigger marker is advanced to start this check without requiring a server command from the user.

The private app currently contains an early WPF shell. The Windows build check for preview `0.1.3-preview.1` succeeded on 2026-11-23 (run [45232055908](https://github.com/loudply0-eng/Xbox-Hub-Builder/actions/runs/45232055908)). No artifacts were uploaded. The in-app release history is implemented; verified package downloads, installation, runtime integrations, packaging, and code signing are not production-ready.

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
