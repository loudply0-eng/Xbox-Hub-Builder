# Xbox Hub Builder

Public repository for reviewed build automation only.

## Security boundary

- Application source of truth: [loudply0-eng/Xbox-Hub-for-PC](https://github.com/loudply0-eng/Xbox-Hub-for-PC) (**private**).
- This repository must contain only generic, reviewed build workflows and scripts.
- Never copy application source, private configuration, signing keys, certificates, access tokens, or user data into this repository.
- Do not upload source archives, checkout directories, private logs, or signing material as workflow artifacts.

## Current workflow

`.github/workflows/private-source-check.yml` is a **manual source-connectivity check**, not an application build. It checks out the private repository on an ephemeral GitHub-hosted runner, prints only a small list of build-manifest paths, and does not upload artifacts.

The private app repository currently contains planning documentation only. A real compile/release workflow must not be added until the Windows application framework and build commands are selected and committed to the private repository.

## Required secret

The workflow uses a dedicated **read-only SSH deploy key** for the private source repository.

- Add the public half of the key to `loudply0-eng/Xbox-Hub-for-PC` as a read-only deploy key.
- Store the private half in this repository's Actions secrets as `SOURCE_REPO_DEPLOY_KEY`.
- Do not enable write access for the deploy key.
- Never paste or commit the private key.

A setup command run from the linked server can use GitHub CLI to generate the key, register the public key, store the private key as an Actions secret, and trigger the manual connectivity check. The GitHub CLI session must have admin access to both repositories and Actions permissions on the builder repository.

## Run

Open **Actions**, select **Private source connectivity check**, and run it on `main`. The job deliberately refuses to run from any branch other than `main`. Do not add pull-request or push triggers to jobs that access the private-source secret.

## Future build workflow

A production build pipeline will be added only after the app framework is selected. Windows compilation should run on a Windows hosted runner. Signing must be handled separately in a trusted, protected environment; this public repository must not contain release signing keys.
