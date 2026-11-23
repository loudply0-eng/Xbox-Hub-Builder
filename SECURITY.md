# Security Policy

This is a public build-automation repository that has access to a private source repository through a dedicated read-only SSH deploy key. Treat every workflow change as security-sensitive.

## Credential rules

- The source credential must be a deploy key registered only on `loudply0-eng/Xbox-Hub-for-PC`.
- The deploy key must be read-only; never enable write access.
- Store the private key only as the Actions secret `SOURCE_REPO_DEPLOY_KEY`.
- Keep the public key registered as a deploy key on the private source repository.
- Never echo, print, commit, or upload the private key.
- Rotate and replace the deploy key immediately if exposure is suspected.

## Workflow rules

- The private-source check is manual-only and restricted to the default `main` branch.
- Do not add `pull_request`, `pull_request_target`, `workflow_run`, or untrusted external triggers to jobs that access private-source secrets.
- Keep `GITHUB_TOKEN` permissions at the minimum required.
- Pin third-party Actions to full commit SHAs and review upstream changes before updating pins.
- Do not run scripts, package hooks, build steps, or downloaded binaries from the private source until their security impact has been reviewed.
- Do not upload private source, source archives, signing files, or logs containing sensitive paths or data as artifacts.
- Keep signing keys and release credentials out of this public repository.

## Reporting

Do not disclose secrets or private source in a public issue. Contact the repository owner privately to report a suspected vulnerability.
