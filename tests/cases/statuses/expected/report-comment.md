## Container scan comparison

**Image:** `test/image:1`

### Results per tool

Counts are unique vulnerability IDs (CVE where resolvable) at the highest severity the tool assigned. *Rows* = raw (vulnerability, package) findings.

| Tool | Status | Version | Critical | High | Medium | Low | Unknown | Unique vulns | Fixable | Rows |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Trivy | ❌ failed (no JSON output) | 0.76.0 | | | | | | | | |
| Grype | ❌ missing (no artifact: job failed or was cancelled) |  | | | | | | | | |
| Docker Scout | ⏭️ skipped (no Docker Hub credentials) |  | | | | | | | | |
| OSV-Scanner | ❌ failed (could not parse output, see the report job log) |  | | | | | | | | |
| Snyk | ❌ failed (no output, see the job log) |  | | | | | | | | |
| FOSSA | ✅ ok | 3.20.5 | 0 | 0 | 0 | 0 | 0 | **0** | 0 | 0 |

> **FOSSA** reported no vulnerabilities. Check its job log: this usually means the tool has no advisory data for this image's OS (for example an end-of-life distribution), not that the image is clean.

### Agreement between tools

0 unique vulnerabilities across 1 tools.

| Found by N tools | 1 |
|---|---:|
| Vulnerabilities | 0 |

**Pairwise overlap** (shared vulnerability IDs; diagonal = tool total):

| | FOSSA |
|---|---:|
| FOSSA | **0** |

| Tool | Only found by this tool | Missed (found by all other tools) |
|---|---:|---:|
| FOSSA | 0 | 0 |

0 vulnerabilities were rated with different severities by different tools.

### Critical and High vulnerabilities (0 total, showing up to 50)

Ordered by severity, then by how many tools agree. Severity is the highest any tool assigned.

| Vulnerability | Severity | Package(s) | Fixed in | FOSSA |
|---|---|---|---|:---:|

_Per-tool details, `findings.json` and `findings.csv` are in the `scan-report` artifact._
