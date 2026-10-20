#!/usr/bin/env bash
# Aggregate container scan results from several tools into one Markdown report.
#
# Expects one directory per tool under --in (as produced by actions/download-artifact
# with `pattern: scan-*`), each holding the tool's raw output plus a meta.json:
#
#   artifacts/scan-trivy/{trivy.json,meta.json}
#   artifacts/scan-grype/{grype.json,meta.json}
#   ...
#
# meta.json: {"status": "ok|skipped|failed", "version": "...", "reason": "..."}
#
# Writes to --out:
#   report.md          full report (job summary)
#   report-comment.md  trimmed report (PR comment, < 65,536 chars)
#   findings.json/csv  normalized rows: tool, vuln, native_id, pkg, version, fixed, severity
#
# With --fail-on <critical|high|medium|low> (any case), writes gate=fail|pass and
# gate-reason to $GITHUB_OUTPUT. The gate also fails when a tool failed or left no
# artifact, so a broken scan can't pass as a clean one; skipped tools don't count.
# The script itself always exits 0 on success so the report is still published.
#
# Requires bash 4+ and jq 1.7+ (both preinstalled on ubuntu-latest runners).
set -euo pipefail

IN=artifacts
OUT=report
IMAGE=${SCAN_IMAGE:-}
FAIL_ON=none
COMMENT_LIMIT=60000

while [[ $# -gt 0 ]]; do
  case $1 in
    --in)
      IN=$2
      shift 2
      ;;
    --out)
      OUT=$2
      shift 2
      ;;
    --image)
      IMAGE=$2
      shift 2
      ;;
    --fail-on)
      FAIL_ON=$2
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^set /{/^#/p;}' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

FAIL_ON=${FAIL_ON,,}
case $FAIL_ON in
  none | critical | high | medium | low) ;;
  *)
    echo "--fail-on must be none, critical, high, medium or low, not '$FAIL_ON'" >&2
    exit 2
    ;;
esac

# scan/2 is the newest builtin used here; jq 1.6 lacks it and every parser would fail.
if ! jq -n '"a" | scan("a"; "g")' >/dev/null 2>&1; then
  echo "needs jq 1.7 or later (found: $(jq --version 2>&1))" >&2
  exit 2
fi

# Order here is the column order in the report.
TOOLS=(trivy grype scout osv snyk fossa)
declare -A NAME=(
  [trivy]="Trivy" [grype]="Grype" [scout]="Docker Scout" [osv]="OSV-Scanner"
  [snyk]="Snyk" [fossa]="FOSSA"
)

# --------------------------------------------------------------------------- jq library
# Severity order, most severe first, shared by the per-tool dedup, the report and the gate.
# rank is case-insensitive so it also ranks --fail-on values; anything else sorts last.
read -r -d '' SEV <<'JQ' || true
def sevs: ["Critical", "High", "Medium", "Low", "Unknown"];
def rank: ascii_downcase as $s | sevs | map(ascii_downcase) | index($s) // length;
JQ

# emit(...) turns one tool record into normalized rows: one per CVE the record refers
# to (else per GHSA id, else the tool's native id), with severity mapped to
# Critical/High/Medium/Low/Unknown (labels or CVSS scores).
read -r -d '' LIB <<'JQ' || true
def norm_sev:
  if . == null then "Unknown"
  elif type == "number" or (tostring | test("^[0-9]+(\\.[0-9]+)?$")) then
    (tonumber) as $s
    | if $s >= 9 then "Critical" elif $s >= 7 then "High" elif $s >= 4 then "Medium"
      elif $s > 0 then "Low" else "Unknown" end
  else
    (tostring | ascii_downcase) as $v
    | if $v == "critical" then "Critical"
      elif $v == "high" or $v == "important" or $v == "error" then "High"
      elif $v == "medium" or $v == "moderate" or $v == "warning" then "Medium"
      elif $v == "low" or $v == "negligible" or $v == "minor" or $v == "note" then "Low"
      else "Unknown" end
  end;
def cves: [.. | strings | scan("CVE-[0-9]{4}-[0-9]{4,}"; "i") | ascii_upcase] | unique;
# GitHub advisory ids, for advisories that have no CVE.
def ghsas: [.. | strings | scan("GHSA(?:-[0-9a-z]{4}){3}"; "i") | "GHSA" + (.[4:] | ascii_downcase)] | unique;
def str: if . == null then "" elif type == "array" then map(tostring) | join(", ") else tostring end;
# Placeholders tools write instead of a fixed version (Scout: "not fixed", FOSSA: "NO_SAFE_VERSION").
def fixed_str: str | if test("^(not fixed|no_safe_version|none|n/a)$"; "i") then "" else . end;
# Percent-decodes ASCII escapes such as %40 and %2B, which is all purls need
# (jq 1.7 has no @urid).
def urid:
  gsub("%(?<h>[0-9A-Fa-f]{2})";
    .h | ascii_downcase | explode | map(if . >= 97 then . - 87 else . - 48 end)
    | [.[0] * 16 + .[1]] | implode);
# {name, version} from a purl, named like the other tools do: OS package namespaces are
# the distro and are dropped, other namespaces are part of the name (npm scopes, Go
# module paths, Maven groups).
def purl:
  (capture("^pkg:(?<t>[^/]+)/(?<p>.+?)@(?<v>[^@?#]+)") // null)
  | if . == null then {name: "", version: ""} else
      (.p | split("/") | map(urid)) as $s
      | ($s[:-1] | join("/")) as $ns
      | {name: (if $ns == "" or (.t | IN("deb", "rpm", "apk", "alpm")) then $s[-1]
                elif .t == "maven" then "\($ns):\($s[-1])"
                else "\($ns)/\($s[-1])" end),
         version: (.v | urid)}
    end;
def emit($tool; $id; $sources; $pkg; $ver; $fixed; $sev):
  ([$id, $sources] | cves) as $c
  | (if ($c | length) > 0 then $c else [$id, $sources] | ghsas end) as $c
  | (if ($c | length) > 0 then $c[] else ($id | str) end) as $v
  | {tool: $tool, vuln: $v, native_id: ($id | str), pkg: ($pkg | str),
     version: ($ver | str), fixed: ($fixed | fixed_str), severity: ($sev | norm_sev)};
def sarif($tool):
  .runs[]?
  | ((.tool.driver.rules // []) | map({key: .id, value: .}) | from_entries) as $R
  | .results[]?
  | ($R[.ruleId] // {}) as $r
  | (($r.properties // {}) + (.properties // {})) as $p
  # A rule lists every affected package version; the result's message names the one it
  # is about ("Package : pkg:npm/jsonwebtoken@0.4.0").
  | ((.message.text // "" | capture("Package\\s*:\\s*(?<p>pkg:\\S+)").p)
     // (($p.purls // []) | if length == 1 then .[0] else null end)
     // "" | purl) as $purl
  | emit($tool; (.ruleId // $r.name); [$r.name, .message.text];
         (if $purl.name != "" then $purl.name else ($p.package // $p.packageName) end);
         (if $purl.version != "" then $purl.version else ($p.affected_version // $p.installedVersion) end);
         ($p.fixed_version // $p.fixedVersion);
         ($p.cvssV3_severity // $p.severity // $p["security-severity"] // .level));
JQ

# --------------------------------------------------------------------------- per-tool parsers
# Each prints normalized rows (one JSON object per line) for the files in "$1".
parse_trivy() {
  jq -c "$LIB"'.Results[]?.Vulnerabilities[]?
    | emit("trivy"; .VulnerabilityID; .VendorIDs; .PkgName; .InstalledVersion; .FixedVersion; .Severity)' \
    "$1/trivy.json"
}
parse_grype() {
  jq -c "$LIB"'.matches[]?
    | emit("grype"; .vulnerability.id; [.relatedVulnerabilities[]?.id]; .artifact.name;
           .artifact.version; .vulnerability.fix.versions; .vulnerability.severity)' \
    "$1/grype.json"
}
parse_scout() { jq -c "$LIB"'sarif("scout")' "$1/scout.sarif"; }
# OSV records have no fixed version per finding, only ranges of `introduced`/`fixed`
# events. A record lists one entry per ecosystem release (Debian:12, Debian:13, ...) and
# can have several ranges (uuid: fixed in 11.1.1, 12.0.1 and 13.0.1), so the fix comes
# from the range of this package's ecosystem that contains the installed version.
parse_osv() {
  jq -c "$LIB"'
    # Approximate version order: digit runs compare as numbers, everything else as text.
    def vkey: [scan("[0-9]+|[^0-9]+") | tonumber? // .];
    def osv_fix($v):
      ($v | vkey) as $k
      | first(.[] | .events // [] | . as $e | range(0; length - 1)
          | select($e[.].introduced != null and $e[. + 1].fixed != null
                   and ($e[.].introduced | vkey) <= $k and $k < ($e[. + 1].fixed | vkey))
          | $e[. + 1].fixed) // "";
    .results[]?.packages[]?
    | .package as $p | (.vulnerabilities // []) as $vs
    | .groups[]? | . as $g
    | [$vs[] | select(.id as $i | $g.ids | index($i))
       | .affected[]?
       | select((.package.name // $p.name) == $p.name)
       | select(.package.ecosystem == null or $p.ecosystem == null or .package.ecosystem == $p.ecosystem)
       | .ranges[]? | select(.type != "GIT")] as $ranges
    | emit("osv"; .ids[0]; [.ids, .aliases];
           # `name` is the source package; `os_package_name` is the installed binary package.
           ($p.os_package_name // $p.name); $p.version; ($ranges | osv_fix($p.version)); .max_severity)' \
    "$1/osv.json"
}
parse_snyk() {
  # Container JSON: OS packages at the top level, application projects (npm, maven, ...)
  # nested under .applications[]. License issues are skipped.
  jq -c "$LIB"'(if type == "array" then .[] else . end) | (., .applications[]?) | .vulnerabilities[]?
    | select(.type != "license")
    # For OS packages `name` is "source/binary" and `packageName` the source; report the
    # binary like the other tools do. Other names can contain "/" too (@babel/core).
    | (.packageName // "") as $src
    | emit("snyk"; .id; [.identifiers.CVE, .identifiers.GHSA];
           ((.name // $src) | ltrimstr($src + "/")); .version; .fixedIn; .severity)' \
    "$1/snyk.json"
}
# `fossa container test --format json`: {count, issues: [{type, cve, fixedIn, priorityString,
# revisionId: locator}]}, e.g. "npm+lodash$2.4.2" or "deb+zlib1g#debian#13$amd64#1:1.3".
# Licensing and policy issues are skipped.
parse_fossa() {
  jq -c "$LIB"'.issues[]? | select(.type == "vulnerability")
    | ((.revisionId // "") | capture("^(?:[^+]*\\+)?(?<pkg>[^#$]*)[^$]*\\$(?:[^#]*#)?(?<ver>.*)$") // {pkg: "", ver: ""}) as $loc
    | emit("fossa"; (.cve // "FOSSA-\(.id)"); []; $loc.pkg; $loc.ver; .fixedIn; .priorityString)' \
    "$1/fossa.json"
}

# Image digest, when a tool reports it.
digest_of() {
  case $1 in
    trivy) jq -r '.Metadata.RepoDigests[0] // empty' "$2/trivy.json" ;;
    grype) jq -r '.source.target.repoDigests[0] // empty' "$2/grype.json" ;;
  esac 2>/dev/null || true
}

# --------------------------------------------------------------------------- collect
mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
: >"$work/tools.ndjson"
: >"$work/rows.ndjson"

for t in "${TOOLS[@]}"; do
  d="$IN/scan-$t"
  status=missing version="" reason="no artifact: job failed or was cancelled" digest=""
  if [[ -d $d ]]; then
    status=ok reason=""
    if [[ -f $d/meta.json ]]; then
      status=$(jq -r '.status // "ok"' "$d/meta.json")
      version=$(jq -r '.version // ""' "$d/meta.json")
      reason=$(jq -r '.reason // ""' "$d/meta.json")
      [[ $status == failed && -z $reason ]] && reason="no output, see the job log"
    fi
    if [[ $status == ok ]]; then
      if parse_"$t" "$d" >"$work/$t.ndjson" 2>"$work/$t.err"; then
        # One row per (vuln, package, version), keeping the highest severity:
        # tools such as Snyk repeat a vuln once per dependency path.
        jq -sc "$SEV"'sort_by(.severity | rank) | unique_by([.vuln, .pkg, .version]) | .[]' \
          "$work/$t.ndjson" >>"$work/rows.ndjson"
        digest=$(digest_of "$t" "$d")
      else
        status=failed
        reason="could not parse output, see the report job log"
        # jq's error text differs between jq versions, so keep it out of the report.
        echo "::warning::${NAME[$t]}: could not parse output: $(head -c 500 "$work/$t.err" | tr '\n' ' ')" >&2
      fi
    fi
  fi
  jq -nc --arg key "$t" --arg name "${NAME[$t]}" --arg status "$status" \
    --arg version "$version" --arg reason "$reason" --arg digest "$digest" \
    '$ARGS.named' >>"$work/tools.ndjson"
  printf '%-14s %-8s %6s rows %s\n' "${NAME[$t]}" "$status" \
    "$(jq -s --arg t "$t" 'map(select(.tool == $t)) | length' "$work/rows.ndjson")" "$reason"
done

# --------------------------------------------------------------------------- report
run_url=""
if [[ -n ${GITHUB_RUN_ID:-} ]]; then
  run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

read -r -d '' REPORT <<'JQ' || true
def esc: tostring | gsub("\\|"; "\\|") | gsub("\n"; " ");
def link:
  if test("^CVE-") then "[\(.)](https://nvd.nist.gov/vuln/detail/\(.))"
  elif test("^GHSA-") then "[\(.)](https://github.com/advisories/\(.))"
  else . end;
def best: min_by(rank);
def known_best: map(select(. != "Unknown")) | if length == 0 then "Unknown" else best end;

$tools as $T
| ($T | map(select(.status == "ok"))) as $ok
| ($ok | length) as $n
| $rows as $F
# tool -> vuln -> {sev, fixable}
| ($F | group_by(.tool) | map({key: .[0].tool, value: (
      group_by(.vuln) | map({key: .[0].vuln, value: {
        sev: (map(.severity) | best), fixable: any(.[]; .fixed != "")}}) | from_entries)})
   | from_entries) as $PT
# one entry per vuln across tools
| ($F | group_by(.vuln) | map({
      vuln: .[0].vuln,
      tools: (group_by(.tool) | map({key: .[0].tool, value: (map(.severity) | best)}) | from_entries),
      pkgs: (map(select(.pkg != "") | "\(.pkg) \(.version)" | rtrimstr(" ")) | unique),
      fixed: (map(select(.fixed != "") | .fixed) | unique)})
   | map(. + {sev: ([.tools[]] | known_best)})) as $V
| ($T | map(.digest | select(. != "")) | first // "") as $digest
| [
  "## Container scan comparison", "",
  "**Image:** `\($image)`"
    + (if $digest != "" then "  \n**Digest:** `\($digest)`" else "" end)
    + (if $run != "" then "  \n**Run:** \($run)" else "" end), "",

  "### Results per tool", "",
  "Counts are unique vulnerability IDs (CVE where resolvable) at the highest severity the tool assigned. *Rows* = raw (vulnerability, package) findings.", "",
  "| Tool | Status | Version | \(sevs | join(" | ")) | Unique vulns | Fixable | Rows |",
  "|---|---|---|" + ("---:|" * (sevs | length + 3)),
  ($T[] | . as $t
    | ({"ok": "✅ ok", "skipped": "⏭️ skipped", "failed": "❌ failed", "missing": "❌ missing"}[.status]
       + (if .reason != "" then " (\(.reason | esc))" else "" end)) as $st
    | if .status != "ok" then "| \(.name) | \($st) | \(.version | esc) |" + (" |" * (sevs | length + 3))
      else ($PT[.key] // {}) as $m
      | "| \(.name) | \($st) | \(.version | esc) | "
        + (sevs | map(. as $s | [$m[] | select(.sev == $s)] | length | tostring) | join(" | "))
        + " | **\($m | length)** | \([$m[] | select(.fixable)] | length) | \([$F[] | select(.tool == $t.key)] | length) |"
      end),
  "",
  # Call out results that look like a tool limitation rather than a clean image.
  ($ok[] | ($PT[.key] // {}) as $m
    | if ($m | length) == 0 then
        "> **\(.name)** reported no vulnerabilities. Check its job log: this usually means the tool has no advisory data for this image's OS (for example an end-of-life distribution), not that the image is clean.\n"
      elif all($m[]; .sev == "Unknown") then
        "> **\(.name)** assigned no severity to any finding, so all of them count as *Unknown*. The comparison below still uses the severity other tools gave the same vulnerability.\n"
      else empty end),

  if $n == 0 then "_No tool produced results._", "" else

  "### Agreement between tools", "",
  "\($V | length) unique vulnerabilities across \($n) tools.", "",
  "| Found by N tools | \([range(1; $n + 1) | tostring] | join(" | ")) |",
  "|---|" + ("---:|" * $n),
  "| Vulnerabilities | \([range(1; $n + 1) as $k | [$V[] | select(.tools | length == $k)] | length | tostring] | join(" | ")) |",
  "",
  "**Pairwise overlap** (shared vulnerability IDs; diagonal = tool total):", "",
  "| | \($ok | map(.name) | join(" | ")) |",
  "|---|" + ("---:|" * $n),
  ($ok[] as $a
    | "| \($a.name) | "
      + ([$ok[] as $b | [$V[] | select(.tools[$a.key] and .tools[$b.key])] | length
          | if $a.key == $b.key then "**\(.)**" else tostring end] | join(" | "))
      + " |"),
  "",
  "| Tool | Only found by this tool | Missed (found by all other tools) |",
  "|---|---:|---:|",
  ($ok[] as $a
    | ($ok | map(.key) | map(select(. != $a.key))) as $others
    | "| \($a.name) | \([$V[] | select(.tools | keys == [$a.key])] | length) | "
      + "\(if ($others | length) == 0 then 0 else
            [$V[] | select((.tools[$a.key] | not) and (. as $v | all($others[]; $v.tools[.])))] | length end) |"),
  "",
  "\([$V[] | select([.tools[] | select(. != "Unknown")] | unique | length > 1)] | length) vulnerabilities were rated with different severities by different tools.",
  "",

  ([$V[] | select(.sev == "Critical" or .sev == "High")]
   | sort_by([(.sev | rank), -(.tools | length), .vuln])) as $top
  | "### Critical and High vulnerabilities (\($top | length) total, showing up to \($toplimit))", "",
    "Ordered by severity, then by how many tools agree. Severity is the highest any tool assigned.", "",
    "| Vulnerability | Severity | Package(s) | Fixed in | \($ok | map(.name) | join(" | ")) |",
    "|---|---|---|---|" + (":---:|" * $n),
    ($top[:$toplimit][]
      | . as $e
      | "| \(.vuln | link) | \(.sev) | "
        + ((.pkgs[:3] | join(", ")) + (if (.pkgs | length) > 3 then " +\(.pkgs | length - 3)" else "" end) | esc)
        + " | " + ((.fixed[:2] | join(", ")) + (if (.fixed | length) > 2 then " …" else "" end) | esc)
        + " | " + ($ok | map(if $e.tools[.key] then "✓" else "" end) | join(" | ")) + " |"),
    "",

  if $mode == "comment" then
    "_Per-tool details, `findings.json` and `findings.csv` are in the `scan-report` artifact"
      + (if $run != "" then " of the [workflow run](\($run))" else "" end) + "._"
  else
    "### Details per tool", "",
    ($ok[] as $t
      | ($F | map(select(.tool == $t.key)) | sort_by([(.severity | rank), .vuln, .pkg])) as $r
      | "<details><summary>\($t.name): \($r | length) findings (showing up to \($detaillimit))</summary>", "",
        "| Vulnerability | Severity | Package | Installed | Fixed in | Tool ID |",
        "|---|---|---|---|---|---|",
        ($r[:$detaillimit][]
          | "| \(.vuln | link) | \(.severity) | \(.pkg | esc) | \(.version | esc) | \(.fixed | esc) | "
            + "\(if .native_id == .vuln then "" else (.native_id | esc) end) |"),
        "", "</details>", "")
  end
  end
] | join("\n")
JQ

render() {
  jq -nr --slurpfile tools "$work/tools.ndjson" --slurpfile rows "$work/rows.ndjson" \
    --arg image "$IMAGE" --arg run "$run_url" --arg mode "$1" \
    --argjson toplimit 50 --argjson detaillimit 100 \
    "$SEV$REPORT"
}
render full >"$OUT/report.md"
render comment >"$OUT/report-comment.md"

if (($(wc -c <"$OUT/report-comment.md") > COMMENT_LIMIT)); then
  head -c "$COMMENT_LIMIT" "$OUT/report-comment.md" | sed '$d' >"$work/c.md"
  printf '\n\n_…truncated, see the workflow run for the full report._\n' >>"$work/c.md"
  mv "$work/c.md" "$OUT/report-comment.md"
fi

jq -s --arg image "$IMAGE" --slurpfile tools "$work/tools.ndjson" \
  '{image: $image, tools: $tools, findings: .}' "$work/rows.ndjson" >"$OUT/findings.json"
{
  echo '"tool","vuln","native_id","pkg","version","fixed","severity"'
  jq -r '[.tool, .vuln, .native_id, .pkg, .version, .fixed, .severity] | @csv' "$work/rows.ndjson"
} >"$OUT/findings.csv"

# --------------------------------------------------------------------------- gate
# Fails closed: a tool that failed or left no artifact found nothing, which is not the
# same as finding no vulnerabilities. Skipped tools (no credentials) don't count.
if [[ $FAIL_ON != none ]]; then
  reason=$(jq -nr --arg on "$FAIL_ON" \
    --slurpfile tools "$work/tools.ndjson" --slurpfile rows "$work/rows.ndjson" "$SEV"'
    ($on | rank) as $th
    | ([$rows[] | select((.severity | rank) <= $th) | .vuln] | unique | length) as $hits
    | [$tools[] | select(.status == "failed" or .status == "missing") | .name] as $bad
    | [ if $hits > 0 then "\($hits) \(if $hits == 1 then "vulnerability" else "vulnerabilities" end) rated \($on) or higher" else empty end,
        if ($bad | length) > 0 then "no results from \($bad | join(", "))" else empty end,
        if all($tools[]; .status != "ok") then "no tool produced results" else empty end ]
    | join("; ")')
  gate=pass
  [[ -n $reason ]] && gate=fail
  echo "Gate (--fail-on $FAIL_ON): $gate${reason:+ ($reason)}"
  {
    echo "gate=$gate"
    echo "gate-reason=$reason"
  } >>"${GITHUB_OUTPUT:-/dev/null}"
fi
