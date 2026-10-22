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

_Per-tool details, `findings.json` and `findings.csv` are in the `scan-report` artifact._
