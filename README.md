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

Create a fine-grained Personal Access Token with access to **only** `loudply0-eng/Xbox-Hub-for-PC` and **Contents: Read-only** permission. Add it to this public repository as an Actions secret named:

`SOURCE_REPO_READ_TOKEN`

Never paste the token into a workflow file, issue, commit, or chat message. Revoke it immediately if exposed.

## Run

1. Add the secret above.
2. Open **Actions**.
3. Select **Private source connectivity check**.
4. Choose **Run workflow** on the `main` branch.

The job deliberately refuses to run from any branch other than `main`. Do not add pull-request or push triggers that expose the private-source token.

## Future build workflow

A production build pipeline will be added only after the app framework is selected. Windows compilation should run on a Windows hosted runner. Signing must be handled separately in a trusted, protected environment; this public repository must not contain release signing keys.
