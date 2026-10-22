## Container scan comparison

**Image:** `test/image:1`

### Results per tool

Counts are unique vulnerability IDs (CVE where resolvable) at the highest severity the tool assigned. *Rows* = raw (vulnerability, package) findings.

| Tool | Status | Version | Critical | High | Medium | Low | Unknown | Unique vulns | Fixable | Rows |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Trivy | ✅ ok | 0.76.0 | 0 | 2 | 0 | 0 | 0 | **2** | 1 | 2 |
| Grype | ⏭️ skipped (not part of this test case) |  | | | | | | | | |
| Docker Scout | ✅ ok | 1.26.0 | 0 | 2 | 0 | 0 | 0 | **2** | 1 | 2 |
| OSV-Scanner | ✅ ok |  | 0 | 3 | 0 | 0 | 0 | **3** | 2 | 3 |
| Snyk | ✅ ok |  | 0 | 2 | 0 | 0 | 0 | **2** | 1 | 2 |
| FOSSA | ⏭️ skipped (not part of this test case) |  | | | | | | | | |

### Agreement between tools

3 unique vulnerabilities across 4 tools.

| Found by N tools | 1 | 2 | 3 | 4 |
|---|---:|---:|---:|---:|
| Vulnerabilities | 1 | 0 | 0 | 2 |

**Pairwise overlap** (shared vulnerability IDs; diagonal = tool total):

| | Trivy | Docker Scout | OSV-Scanner | Snyk |
|---|---:|---:|---:|---:|
| Trivy | **2** | 2 | 2 | 2 |
| Docker Scout | 2 | **2** | 2 | 2 |
| OSV-Scanner | 2 | 2 | **3** | 2 |
| Snyk | 2 | 2 | 2 | **2** |

| Tool | Only found by this tool | Missed (found by all other tools) |
|---|---:|---:|
| Trivy | 0 | 0 |
| Docker Scout | 0 | 0 |
| OSV-Scanner | 1 | 0 |
| Snyk | 0 | 0 |

0 vulnerabilities were rated with different severities by different tools.

### Critical and High vulnerabilities (3 total, showing up to 50)

Ordered by severity, then by how many tools agree. Severity is the highest any tool assigned.

| Vulnerability | Severity | Package(s) | Fixed in | Trivy | Docker Scout | OSV-Scanner | Snyk |
|---|---|---|---|:---:|:---:|:---:|:---:|
| [CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) | High | libc6 2.41-12+deb13u4 |  | ✓ | ✓ | ✓ | ✓ |
| [GHSA-2c2c-3v3v-4w4w](https://github.com/advisories/GHSA-2c2c-3v3v-4w4w) | High | @scope/pkg 1.0.0 | 1.0.1 | ✓ | ✓ | ✓ | ✓ |
| [CVE-2099-0002](https://nvd.nist.gov/vuln/detail/CVE-2099-0002) | High | uuid 12.0.0 | 12.0.1 |  |  | ✓ |  |

### Details per tool

<details><summary>Trivy: 2 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) | High | libc6 | 2.41-12+deb13u4 |  |  |
| [GHSA-2c2c-3v3v-4w4w](https://github.com/advisories/GHSA-2c2c-3v3v-4w4w) | High | @scope/pkg | 1.0.0 | 1.0.1 |  |

</details>

<details><summary>Docker Scout: 2 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) | High | libc6 | 2.41-12+deb13u4 |  |  |
| [GHSA-2c2c-3v3v-4w4w](https://github.com/advisories/GHSA-2c2c-3v3v-4w4w) | High | @scope/pkg | 1.0.0 | 1.0.1 |  |

</details>

<details><summary>OSV-Scanner: 3 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) | High | libc6 | 2.41-12+deb13u4 |  | DEBIAN-CVE-2099-0001 |
| [CVE-2099-0002](https://nvd.nist.gov/vuln/detail/CVE-2099-0002) | High | uuid | 12.0.0 | 12.0.1 | GHSA-3x3x-4c4c-5f5f |
| [GHSA-2c2c-3v3v-4w4w](https://github.com/advisories/GHSA-2c2c-3v3v-4w4w) | High | @scope/pkg | 1.0.0 | 1.0.1 |  |

</details>

<details><summary>Snyk: 2 findings (showing up to 100)</summary>

| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |
|---|---|---|---|---|---|
| [CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) | High | libc6 | 2.41-12+deb13u4 |  | SNYK-DEBIAN13-GLIBC-1000001 |
| [GHSA-2c2c-3v3v-4w4w](https://github.com/advisories/GHSA-2c2c-3v3v-4w4w) | High | @scope/pkg | 1.0.0 | 1.0.1 | SNYK-JS-SCOPEPKG-1000002 |

</details>

