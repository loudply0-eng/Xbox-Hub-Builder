# Security Policy

This public repository contains workflows that can read the private Xbox Hub source repository. Treat every workflow change as security-sensitive.

## Credential rules

- The source credential must be a dedicated deploy key registered only on `loudply0-eng/Xbox-Hub-for-PC`.
- The deploy key must remain read-only.
- Store the private key only as the Actions secret `SOURCE_REPO_DEPLOY_KEY`.
- Never echo, print, commit, or upload the private key.
- Rotate and replace the deploy key immediately if exposure is suspected.

## Workflow rules

- Private-source workflows must be manually dispatched from the trusted `main` branch only.
- Do not add `pull_request`, `pull_request_target`, `workflow_run`, or untrusted external triggers to jobs that access the private-source secret.
- Keep `GITHUB_TOKEN` permissions at the minimum required (`contents: read` for current workflows).
- Pin third-party Actions to reviewed full commit SHAs and review updates before merging.
- Keep `persist-credentials: false` on private-source checkout.
- Do not print private source, credentials, or secret-bearing URLs.
- Do not upload source trees, private logs, signing files, or credentials as artifacts.
- Do not add release-signing secrets to this public repository.

## Trusted-branch risk

Anyone who can change a secret-bearing workflow on `main` and run it with access to the secret could attempt to exfiltrate private source or the credential. Restrict write access to trusted maintainers and review every workflow change before dispatch.

## Reporting

Do not disclose secrets or private source in a public issue. Contact the repository owner privately to report a suspected vulnerability.
