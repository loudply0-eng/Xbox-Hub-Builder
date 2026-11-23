# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository must contain only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, or user data into this repository.
- Do not upload source archives, checkout directories, private logs, or signing material as workflow artifacts.

## Current workflow

`.github/workflows/private-source-check.yml` is a **manual source-connectivity check**, not an application build. It checks out the private repository on an ephemeral GitHub-hosted runner, reports only whether checkout succeeded and the number of possible build manifests, and does not print source contents or upload artifacts.

The latest recorded connectivity check completed successfully on 2026-11-23, and the run had no artifacts. The private app repository currently contains planning documentation only; no application build manifest exists yet.

A real compile/release workflow must not be added until the Windows application framework and build commands are selected and committed to the private repository.

## Required secret

The workflow uses a dedicated **read-only SSH deploy key** for the private source repository.

- The public half is registered as a read-only deploy key on `loudply0-eng/Xbox-Hub-for-PC`.
- The private half is stored only in this repository's Actions secrets as `SOURCE_REPO_DEPLOY_KEY`.
- The key must remain read-only.
- Never paste, print, commit, or upload the private key.

## Dependency maintenance

`.github/dependabot.yml` checks GitHub Actions references weekly. Review Dependabot pull requests and retain full-SHA pinning when updating Actions.

## Run

Open **Actions**, select **Private source connectivity check**, and run it on `main`. The job deliberately refuses to run from any branch other than `main`. Do not add pull-request or push triggers to jobs that access the private-source secret.

## Future build workflow

A production build pipeline will be added only after the app framework is selected. Windows compilation should run on a Windows hosted runner. Signing must be handled separately in a trusted, protected environment; this public repository must not contain release signing keys.
