## Container scan comparison

**Image:** `test/image:1`  
**Digest:** `bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`

### Results per tool

Counts are unique vulnerability IDs (CVE where resolvable) at the highest severity the tool assigned. *Rows* = raw (vulnerability, package) findings.

| Tool | Status | Version | Critical | High | Medium | Low | Unknown | Unique vulns | Fixable | Rows |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Trivy | ✅ ok | 0.76.0 | 2 | 0 | 1 | 1 | 0 | **4** | 2 | 5 |
| Grype | ✅ ok | 0.121.0 | 2 | 0 | 0 | 1 | 0 | **3** | 1 | 4 |
| Docker Scout | ✅ ok | 1.25.0 | 2 | 1 | 1 | 0 | 1 | **5** | 3 | 7 |
| OSV-Scanner | ✅ ok |  | 1 | 2 | 0 | 0 | 2 | **5** | 3 | 6 |
| Snyk | ✅ ok |  | 1 | 1 | 1 | 2 | 0 | **5** | 2 | 6 |
| FOSSA | ✅ ok | 3.20.5 | 2 | 0 | 1 | 0 | 0 | **3** | 2 | 4 |

### Agreement between tools

11 unique vulnerabilities across 6 tools.

| Found by N tools | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| Vulnerabilities | 7 | 1 | 0 | 1 | 0 | 2 |

**Pairwise overlap** (shared vulnerability IDs; diagonal = tool total):

| | Trivy | Grype | Docker Scout | OSV-Scanner | Snyk | FOSSA |
|---|---:|---:|---:|---:|---:|---:|
| Trivy | **4** | 3 | 2 | 3 | 3 | 2 |
| Grype | 3 | **3** | 2 | 3 | 3 | 2 |
| Docker Scout | 2 | 2 | **5** | 2 | 3 | 2 |
| OSV-Scanner | 3 | 3 | 2 | **5** | 3 | 2 |
| Snyk | 3 | 3 | 3 | 3 | **5** | 2 |
| FOSSA | 2 | 2 | 2 | 2 | 2 | **3** |

| Tool | Only found by this tool | Missed (found by all other tools) |
|---|---:|---:|
| Trivy | 1 | 0 |
| Grype | 0 | 0 |
| Docker Scout | 2 | 0 |
| OSV-Scanner | 2 | 0 |
| Snyk | 1 | 0 |
| FOSSA | 1 | 0 |

2 vulnerabilities were rated with different severities by different tools.

### Critical and High vulnerabilities (5 total, showing up to 50)

Ordered by severity, then by how many tools agree. Severity is the highest any tool assigned.

| Vulnerability | Severity | Package(s) | Fixed in | Trivy | Grype | Docker Scout | OSV-Scanner | Snyk | FOSSA |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken 0.1.0, jsonwebtoken 0.4.0 | 4.2.2, 9.0.0 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress 4.2.1 |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203) | High | lodash 2.4.2 | 4.17.20 |  |  | ✓ |  |  |  |
| [CVE-2026-41907](https://nvd.nist.gov/vuln/detail/CVE-2026-41907) | High | uuid 8.3.2 | 11.1.1 |  |  |  | ✓ |  |  |
| [CVE-2026-41988](https://nvd.nist.gov/vuln/detail/CVE-2026-41988) | High | uuid 8.3.2 | 11.1.1 |  |  |  | ✓ |  |  |

### Details per tool

<details><summary>Trivy: 5 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |  |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |  |
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  |  |
| NSWG-ECO-154 | Medium | sanitize-html | 1.4.2 | >=1.11.4 |  |
| [CVE-2010-4756](https://nvd.nist.gov/vuln/detail/CVE-2010-4756) | Low | libc6 | 2.41-12+deb13u4 |  |  |

</details>

<details><summary>Grype: 4 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.1.0 | 4.2.2 | GHSA-c7hr-j4mj-j2w6 |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.4.0 | 4.2.2 | GHSA-c7hr-j4mj-j2w6 |
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  | GHSA-hrh2-vp3x-79xf |
| [CVE-2010-4756](https://nvd.nist.gov/vuln/detail/CVE-2010-4756) | Low | libc6 | 2.41-12+deb13u4 |  |  |

</details>

<details><summary>Docker Scout: 7 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |  |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |  |
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  |  |
| [CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203) | High | lodash | 2.4.2 | 4.17.20 |  |
| [CVE-2021-32822](https://nvd.nist.gov/vuln/detail/CVE-2021-32822) | Medium | hbs | 4.3.1 |  |  |
| GMS-2015-4 | Unknown | jsonwebtoken | 0.1.0 | 4.2.2 |  |
| GMS-2015-4 | Unknown | jsonwebtoken | 0.4.0 | 4.2.2 |  |

</details>

<details><summary>OSV-Scanner: 6 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  | GHSA-hrh2-vp3x-79xf |
| [CVE-2026-41907](https://nvd.nist.gov/vuln/detail/CVE-2026-41907) | High | uuid | 8.3.2 | 11.1.1 | GHSA-w5hq-g745-h8pq |
| [CVE-2026-41988](https://nvd.nist.gov/vuln/detail/CVE-2026-41988) | High | uuid | 8.3.2 | 11.1.1 | GHSA-w5hq-g745-h8pq |
| [CVE-2010-4756](https://nvd.nist.gov/vuln/detail/CVE-2010-4756) | Unknown | libc6 | 2.41-12+deb13u4 |  | DEBIAN-CVE-2010-4756 |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Unknown | jsonwebtoken | 0.1.0 | 4.2.2 | GHSA-c7hr-j4mj-j2w6 |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Unknown | jsonwebtoken | 0.4.0 | 4.2.2 | GHSA-c7hr-j4mj-j2w6 |

</details>

<details><summary>Snyk: 6 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  | SNYK-JS-DECOMPRESS-20254116 |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | High | jsonwebtoken | 0.1.0 | 4.2.2 | npm:jsonwebtoken:20150331 |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | High | jsonwebtoken | 0.4.0 | 4.2.2 | npm:jsonwebtoken:20150331 |
| [CVE-2020-28500](https://nvd.nist.gov/vuln/detail/CVE-2020-28500) | Medium | lodash | 2.4.2 | 4.17.21 | SNYK-JS-LODASH-1018905 |
| [CVE-2010-4756](https://nvd.nist.gov/vuln/detail/CVE-2010-4756) | Low | libc6 | 2.41-12+deb13u4 |  | SNYK-DEBIAN13-GLIBC-5681058 |
| [CVE-2021-32822](https://nvd.nist.gov/vuln/detail/CVE-2021-32822) | Low | hbs | 4.3.1 |  | SNYK-JS-HBS-1566555 |

</details>

<details><summary>FOSSA: 4 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.1.0 | 9.0.0 |  |
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | Critical | jsonwebtoken | 0.4.0 | 9.0.0 |  |
| [CVE-2026-101894](https://nvd.nist.gov/vuln/detail/CVE-2026-101894) | Critical | decompress | 4.2.1 |  |  |
| [CVE-2025-13465](https://nvd.nist.gov/vuln/detail/CVE-2025-13465) | Medium | lodash | 2.4.2 | 4.18.0 |  |

</details>

