#!/usr/bin/env bash
#------------------------------------------------------------------------------
# wazuh-reload-rules
# Authenticate to Wazuh API, trigger ruleset reload (analysisd), pretty-print
# results with jq, parse issues table, and tail ossec.log.
#------------------------------------------------------------------------------

set -Eeuo pipefail

# -------- Defaults --------
WAZUH_URL="${WAZUH_URL:-https://127.0.0.1:55000}"
WAZUH_USER="${WAZUH_USER:-wazuh}"
WAZUH_PASS="${WAZUH_PASS:-wazuh}"
VERIFY_TLS="${VERIFY_TLS:-false}"
OSSEC_LOG="${OSSEC_LOG:-/var/ossec/logs/ossec.log}"
VERBOSE="${VERBOSE:-false}"
PRINT_TABLE="true"

# -------- Pretty output helpers (all logs to STDERR!) --------
is_tty() { [[ -t 2 ]]; }
if is_tty; then
  BOLD="$(printf '\033[1m')"; RED="$(printf '\033[31m')"; GRN="$(printf '\033[32m')"
  YLW="$(printf '\033[33m')"; BLU="$(printf '\033[34m')"; DIM="$(printf '\033[2m')"
  CLR="$(printf '\033[0m')"
else
  BOLD=""; RED=""; GRN=""; YLW=""; BLU=""; DIM=""; CLR=""
fi

die() { >&2 echo -e "${RED}ERROR:${CLR} $*"; exit 1; }
info(){ >&2 echo -e "${BLU}[*]${CLR} $*"; }
ok()  { >&2 echo -e "${GRN}[✓]${CLR} $*"; }
warn(){ >&2 echo -e "${YLW}[!]${CLR} $*"; }

# -------- Dependencies --------
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq   >/dev/null 2>&1 || die "jq is required"

# -------- Args parsing --------
print_help() {
  cat <<'HLP'
Usage:
  wazuh-reload-rules [-u URL] [-U USER] [-p PASS] [-k] [-L LOG] [-v] [--no-table]

Options:
  -u, --url        Wazuh API URL (default: https://127.0.0.1:55000)
  -U, --user       Wazuh API user (default: wazuh-wui)
  -p, --pass       Wazuh API password (or set WAZUH_PASS)
  -k, --insecure   Skip TLS verification
  -L, --log        Path to ossec.log (default: /var/ossec/logs/ossec.log)
  -v, --verbose    Verbose HTTP
      --no-table   Do not print parsed error table
HLP
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url)      WAZUH_URL="$2"; shift 2 ;;
    -U|--user)     WAZUH_USER="$2"; shift 2 ;;
    -p|--pass)     WAZUH_PASS="${2:-}"; shift 2 ;;
    -k|--insecure) VERIFY_TLS="false"; shift ;;
    -L|--log)      OSSEC_LOG="$2"; shift 2 ;;
    -v|--verbose)  VERBOSE="true"; shift ;;
    --no-table)    PRINT_TABLE="false"; shift ;;
    -h|--help)     print_help ;;
    *) die "Unknown argument: $1 (use -h)";;
  esac
done

# -------- curl flags --------
INSECURE_FLAG=""
[[ "${VERIFY_TLS}" == "false" ]] && INSECURE_FLAG="-k"
CURL_COMMON=(-sS ${INSECURE_FLAG})
[[ "${VERBOSE}" == "true" ]] && CURL_COMMON=(-sS -v ${INSECURE_FLAG})

# -------- HTTP helpers --------
# Return non-zero on 4xx/5xx and print body to STDERR
http_put() {
  local url="$1"; shift
  local out http_code
  out="$(curl "${CURL_COMMON[@]}" -X PUT "$url" "$@" -w $'\n%{http_code}')" || return 1
  http_code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  if [[ "$http_code" =~ ^2..$ ]]; then
    printf '%s' "$out"
    return 0
  else
    >&2 echo -e "${RED}HTTP $http_code${CLR}"
    >&2 printf '%s\n' "$out"
    return 2
  fi
}

# -------- Auth (Basic -> Bearer token) --------
get_token() {
  [[ -n "${WAZUH_PASS}" ]] || die "No password. Set WAZUH_PASS or use -p."
  info "Authenticating to ${WAZUH_URL} as '${WAZUH_USER}'…"

  # Try raw=true (plain token)
  local resp token
  resp="$(curl "${CURL_COMMON[@]}" -u "${WAZUH_USER}:${WAZUH_PASS}" \
          -X POST "${WAZUH_URL}/security/user/authenticate?raw=true")" || die "Auth request failed"
  if [[ "$resp" =~ ^[^.]+\.[^.]+\.[^.]+$ ]]; then
    printf '%s' "$resp"
    return 0
  fi

  # Fallback to JSON
  resp="$(curl "${CURL_COMMON[@]}" -u "${WAZUH_USER}:${WAZUH_PASS}" \
          -X POST "${WAZUH_URL}/security/user/authenticate")" || die "Auth request failed"
  token="$(jq -r '.data.token // empty' <<<"$resp")"
  [[ -n "$token" ]] || die "Auth succeeded but token not found in JSON."
  printf '%s' "$token"
}

# -------- Reload ruleset --------
reload_rules() {
  local token="$1"
  info "Requesting ruleset reload (analysisd)…"
  http_put "${WAZUH_URL}/manager/analysisd/reload?pretty=true" \
           -H "Authorization: Bearer ${token}"
}

# -------- Present result neatly --------
print_reload_summary() {
  local json="$1"

  local error msg total failed
  error="$(jq -r '.error // empty' <<<"$json" 2>/dev/null || true)"
  msg="$(jq -r '.message // "No message"' <<<"$json" 2>/dev/null)"
  total="$(jq -r '.data.total_affected_items // 0' <<<"$json" 2>/dev/null)"
  failed="$(jq -r '.data.total_failed_items // 0' <<<"$json" 2>/dev/null)"

  if [[ "$error" == "0" ]]; then
    ok "API accepted reload request."
  else
    die "API returned error=${error}: ${msg}"
  fi

  >&2 echo -e "${BOLD}Message:${CLR} ${msg}"
  >&2 echo -e "${BOLD}Affected items:${CLR} ${total}, ${BOLD}Failed items:${CLR} ${failed}"

  # Bullet list
  if jq -e '.data.affected_items[]? | select(.msg and (.msg|length>0))' >/dev/null 2>&1 <<<"$json"; then
    >&2 echo -e "${BOLD}Details:${CLR}"
    jq -r '
      .data.affected_items[]?
      | select(.msg)
      | .msg
      | split(", ")
      | .[]
      | " - " + .
    ' <<< "$json" >&2
  fi

  # Parsed table
  if [[ "${PRINT_TABLE}" == "true" ]]; then
    echo
    print_error_table "$json" >&2
  fi
}

# -------- Parse affected_items[].msg into a column table --------
print_error_table() {
  local json="$1"
  mapfile -t lines < <(jq -r '
      .data.affected_items[]?
      | select(.msg)
      | .msg
      | split(", ")
      | .[]
    ' <<< "$json" 2>/dev/null || true)

  [[ "${#lines[@]}" -gt 0 ]] || { echo -e "${DIM}(no detailed messages to parse)${CLR}"; return 0; }

  printf "%s\n" "${BOLD}Parsed ruleset issues:${CLR}"
  printf "%-8s  %-16s  %s\n" "Rule" "Issue" "Detail"
  printf "%-8s  %-16s  %s\n" "--------" "----------------" "----------------------------------------------"

  local line rule issue detail
  for line in "${lines[@]}"; do
    rule="?" ; issue="generic" ; detail="${line}"
    if [[ "${line}" =~ Group\ \'([^\']+)\'\ was\ not\ found.*if_group.*Rule\ \'([0-9]+)\' ]]; then
      detail="group='${BASH_REMATCH[1]}'"
      rule="${BASH_REMATCH[2]}"
      issue="if_group_missing"
    elif [[ "${line}" =~ Signature\ ID\ \'([0-9]+)\'\ was\ not\ found.*\'if_sid\'.*rule\ \'([0-9]+)\' ]]; then
      detail="sid=${BASH_REMATCH[1]}"
      rule="${BASH_REMATCH[2]}"
      issue="if_sid_sig_missing"
    elif [[ "${line}" =~ Empty\ \'if_sid\'\ value.*Rule\ \'([0-9]+)\' ]]; then
      rule="${BASH_REMATCH[1]}"
      issue="if_sid_empty"
      detail="if_sid empty"
    elif [[ "${line}" =~ Rule\ \'([0-9]+)\' ]]; then
      rule="${BASH_REMATCH[1]}"
      issue="generic"
      detail="${line}"
    fi
    printf "%-8s  %-16s  %s\n" "${rule}" "${issue}" "${detail}"
  done
}

# -------- Tail ossec.log for context --------
tail_ossec_log() {
  local log="${OSSEC_LOG}"
  if [[ -r "${log}" ]]; then
    >&2 echo
    >&2 echo -e "${DIM}---- Recent ossec.log (ruleset/analysisd) ----${CLR}"
    tail -n 10 "${log}" \
      | grep -Ei 'ruleset|analysisd|rule set|decod' \
      | tail -n 30 || true
    >&2 echo -e "${DIM}----------------------------------------------${CLR}"
  else
    warn "Cannot read ${log} (missing or insufficient perms)."
  fi
}

# -------- Main --------
main() {
  local token reload_json
  token="$(get_token)"              # stdout: token only
  reload_json="$(reload_rules "${token}")" || exit $?

  echo                               # (keep one clean newline on STDOUT)
  print_reload_summary "${reload_json}"
  tail_ossec_log
}

main "$@"
