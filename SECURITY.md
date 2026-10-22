# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security** tab → **Report a vulnerability**
([direct link](https://github.com/svekar/container-scanner-comparison/security/advisories/new)).
Don't open a public issue.

This is a personal project, so there is no fixed response time, but reports are taken seriously.

## Scope

In scope: the workflows in [`.github/`](.github/) and the scripts in this repository, for
example script injection, secret exposure or overly broad token permissions.

Out of scope:
- Vulnerabilities that the scanners find in the scanned image. The default image,
  [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), is vulnerable on purpose.
- Vulnerabilities in the scanners or their GitHub Actions. Report those to their maintainers.
