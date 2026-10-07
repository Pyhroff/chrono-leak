# Security Policy

## Scope

CHRONO-LEAK is a research and educational OSINT self-audit project. Security reports are welcome for the code, dependency handling, local report generation, credential handling, privacy boundaries, and integrations maintained by this repository.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting/security advisory mechanism for this repository when available. Include:

- A clear description of the issue and its security impact.
- The affected file, component, or workflow.
- Reproduction steps or a minimal proof of concept.
- Any relevant logs or screenshots, with secrets and personal data removed.
- A suggested mitigation, if you have one.

Please do not include real credentials, private personal data, or live targets in a report.

## Responsible disclosure

Give maintainers a reasonable opportunity to investigate and fix the issue before public disclosure. Do not access, modify, or exfiltrate data that you do not own or have explicit authorization to assess.

For issues involving third-party services such as GitHub, xAI, or Have I Been Pwned, follow the relevant provider's vulnerability-reporting and acceptable-use requirements as well.

## Supported versions

Only the latest commit on the default main branch is actively maintained for security fixes. Older snapshots may contain known or unfixed issues.

## Security notes for users

- Never commit API keys or other credentials to the repository.
- Keep generated reports under the repository's gitignored reports/ directory.
- Review data before enabling external AI analysis.
- Use CHRONO-LEAK only for your own accounts or assessments you are explicitly authorized to perform.
