# Security Policy

This is a public build-automation repository that may use one read-only credential to retrieve a private source repository. Treat every workflow change as security-sensitive.

## Credential rules

- The only permitted source credential is a fine-grained token scoped to `loudply0-eng/Xbox-Hub-for-PC` with Contents: Read-only access.
- Store it only as the Actions secret `SOURCE_REPO_READ_TOKEN`.
- Never echo, print, encode into logs, place in command-line URLs, or write the token to files.
- Revoke and replace the token immediately if exposure is suspected.

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
