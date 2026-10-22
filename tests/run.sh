#!/usr/bin/env bash
#
# Regression tests for scripts/aggregate.sh.
#
# Each directory under tests/cases/ is one test case:
#   input/      scan-<tool>/ directories, as downloaded from the scan artifacts
#   args        optional extra arguments for aggregate.sh, e.g. "--fail-on high"
#   expected/   report.md, report-comment.md, findings.csv and github_output
#
# Usage:
#   tests/run.sh            run all cases, print a diff for each mismatch
#   tests/run.sh --update   regenerate expected/ from the current script output
#
# The inputs are trimmed copies of real scanner output. After changing a parser,
# run with --update and review the diff of tests/cases/*/expected/ before
# committing.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly AGGREGATE="${ROOT_DIR}/scripts/aggregate.sh"
readonly CASES_DIR="${ROOT_DIR}/tests/cases"
readonly IMAGE="test/image:1"
readonly OUTPUTS=(report.md report-comment.md findings.csv github_output)

#######################################
# Runs aggregate.sh for one test case.
# Arguments:
#   Test case directory.
#   Output directory.
# Outputs:
#   Writes the script's output files and github_output to the output directory.
#   Writes aggregate.sh's stderr to stderr only if it fails.
# Returns:
#   Non-zero if aggregate.sh fails.
#######################################
run_case() {
  local case_dir="$1"
  local out_dir="$2"
  local -a args=()

  if [[ -f "${case_dir}/args" ]]; then
    read -r -a args <"${case_dir}/args"
  fi
  mkdir -p "${out_dir}"
  : >"${out_dir}/github_output"

  # Unset the GitHub run variables so the report has no run URL and is the
  # same locally and in CI. Keep stderr out of the log: some cases make
  # aggregate.sh print a ::warning:: on purpose, which in CI would become an
  # annotation on every run.
  if ! env -u GITHUB_RUN_ID -u GITHUB_REPOSITORY -u GITHUB_SERVER_URL \
    GITHUB_OUTPUT="${out_dir}/github_output" \
    "${AGGREGATE}" --in "${case_dir}/input" --out "${out_dir}" \
    --image "${IMAGE}" "${args[@]}" >/dev/null 2>"${out_dir}/stderr"; then
    cat "${out_dir}/stderr" >&2
    return 1
  fi
}

#######################################
# Compares the output of one test case with its expected files.
# Arguments:
#   Test case directory.
#   Output directory.
# Returns:
#   0 if every output matches, 1 otherwise.
#######################################
check_case() {
  local case_dir="$1"
  local out_dir="$2"
  local file
  local status=0

  for file in "${OUTPUTS[@]}"; do
    if ! diff -u "${case_dir}/expected/${file}" "${out_dir}/${file}"; then
      status=1
    fi
  done
  return "${status}"
}

#######################################
# Checks that aggregate.sh rejects an unknown --fail-on value instead of
# silently turning the gate off.
# Returns:
#   0 if it exits with status 2, 1 otherwise.
#######################################
check_bad_fail_on() {
  local status=0

  "${AGGREGATE}" --in "${WORK_DIR}/none" --out "${WORK_DIR}/bad-fail-on" \
    --fail-on critial 2>/dev/null || status=$?
  ((status == 2))
}

main() {
  local update=false
  local case_dir
  local name
  local file
  local failed=0

  case "${1:-}" in
    --update) update=true ;;
    "") ;;
    *)
      echo "usage: $0 [--update]" >&2
      exit 2
      ;;
  esac

  WORK_DIR="$(mktemp -d)"
  readonly WORK_DIR
  trap 'rm -rf "${WORK_DIR}"' EXIT

  for case_dir in "${CASES_DIR}"/*/; do
    case_dir="${case_dir%/}"
    name="$(basename "${case_dir}")"
    run_case "${case_dir}" "${WORK_DIR}/${name}"

    if [[ "${update}" == true ]]; then
      mkdir -p "${case_dir}/expected"
      for file in "${OUTPUTS[@]}"; do
        cp "${WORK_DIR}/${name}/${file}" "${case_dir}/expected/${file}"
      done
      echo "updated  ${name}"
    elif check_case "${case_dir}" "${WORK_DIR}/${name}"; then
      echo "ok       ${name}"
    else
      echo "FAILED   ${name}"
      failed=$((failed + 1))
    fi
  done

  if check_bad_fail_on; then
    echo "ok       --fail-on rejects unknown values"
  else
    echo "FAILED   --fail-on rejects unknown values"
    failed=$((failed + 1))
  fi

  if ((failed > 0)); then
    echo "${failed} test case(s) failed" >&2
    exit 1
  fi
}

main "$@"
