#!/usr/bin/env bash
#
# f2b - a friendlier wrapper around fail2ban-client
#
# Install:
#   sudo install -m 0750 -o root -g root f2b.sh /usr/local/bin/f2b
#   sudo f2b help
#
# Requires: fail2ban >= 0.10, bash >= 4.2
#
set -Eeuo pipefail
IFS=$'\n\t'

readonly PROG="${0##*/}"
readonly VERSION="1.0.0"

# Managed whitelist drop-in. We never touch the user's jail.local.
readonly IGNORE_DROPIN="/etc/fail2ban/jail.d/zz-f2b-ignoreip.local"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]]; then
    readonly C_RESET=$'\033[0m'
    readonly C_BOLD=$'\033[1m'
    readonly C_DIM=$'\033[2m'
    readonly C_RED=$'\033[31m'
    readonly C_GREEN=$'\033[32m'
    readonly C_YELLOW=$'\033[33m'
    readonly C_CYAN=$'\033[36m'
else
    readonly C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN=''
fi

log_info()  { printf '%s\n' "$*"; }
log_ok()    { printf '%s✔%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
log_warn()  { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_err()   { printf '%s✘%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()       { log_err "$*"; exit 1; }

heading()   { printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "$*" "$C_RESET"; }

# Intentional non-zero returns (e.g. "IP was not banned") set SOFT_FAIL so the
# ERR trap stays quiet and only reports genuinely unhandled failures.
SOFT_FAIL=0
on_err() {
    local rc=$1 line=$2
    (( SOFT_FAIL )) && return 0
    log_err "aborted at line $line (exit $rc)"
}
trap 'on_err $? $LINENO' ERR

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
require_root() {
    [[ $EUID -eq 0 ]] || die "must run as root (the fail2ban socket is root-owned). Try: sudo $PROG $*"
}

require_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 \
        || die "fail2ban-client not found in PATH"
    fail2ban-client ping >/dev/null 2>&1 \
        || die "fail2ban server is not responding. Check: systemctl status fail2ban"
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Accepts IPv4, IPv6, and CIDR notation for either.
valid_ip() {
    local ip="$1"
    # IPv4 / IPv4 CIDR
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]; then
        local addr="${ip%%/*}" octet
        local -a octets=()
        IFS='.' read -r -a octets <<< "$addr"
        for octet in "${octets[@]}"; do
            (( octet <= 255 )) || return 1
        done
        return 0
    fi
    # IPv6 / IPv6 CIDR (loose but rejects shell-hostile input)
    if [[ $ip =~ ^[0-9A-Fa-f:]+(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$ ]] && [[ $ip == *:* ]]; then
        return 0
    fi
    return 1
}

assert_ip() {
    valid_ip "$1" || die "'$1' is not a valid IPv4/IPv6 address or CIDR block"
}

# ---------------------------------------------------------------------------
# fail2ban introspection
# ---------------------------------------------------------------------------

# Prints one jail name per line.
get_jails() {
    fail2ban-client status 2>/dev/null \
        | sed -n 's/^.*Jail list:[[:space:]]*//p' \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -v '^$' || true
}

jail_exists() {
    local jail="$1"
    get_jails | grep -qxF "$jail"
}

assert_jail() {
    local jail="$1"
    jail_exists "$jail" || die "jail '$jail' does not exist. Run: $PROG jails"
}

# Prints one banned IP per line for the given jail.
get_banned() {
    local jail="$1"
    fail2ban-client status "$jail" 2>/dev/null \
        | sed -n 's/^.*Banned IP list:[[:space:]]*//p' \
        | tr ' ' '\n' \
        | grep -v '^$' || true
}

# Reads a single numeric/string property from a jail, empty on failure.
jail_prop() {
    local jail="$1" prop="$2"
    fail2ban-client get "$jail" "$prop" 2>/dev/null | tail -1 || true
}

# Resolve where fail2ban writes its own log. Echoes either a file path
# or the literal string "journal".
resolve_logfile() {
    local target
    target="$(fail2ban-client get logtarget 2>/dev/null | tail -1 || true)"
    case "$target" in
        /*)             printf '%s\n' "$target" ;;
        SYSLOG|SYSTEMD) printf 'journal\n' ;;
        *)
            if [[ -r /var/log/fail2ban.log ]]; then
                printf '/var/log/fail2ban.log\n'
            else
                printf 'journal\n'
            fi
            ;;
    esac
}

# Streams fail2ban's log to stdout regardless of backend.
# $1 = number of trailing lines (0 = whole log)
read_log() {
    local lines="${1:-0}" src
    src="$(resolve_logfile)"
    if [[ $src == "journal" ]]; then
        if (( lines > 0 )); then
            journalctl -u fail2ban --no-pager -n "$lines" 2>/dev/null || true
        else
            journalctl -u fail2ban --no-pager 2>/dev/null || true
        fi
    else
        [[ -r $src ]] || { log_warn "cannot read $src"; return 0; }
        # Include rotated logs so history survives logrotate.
        if (( lines > 0 )); then
            tail -n "$lines" "$src"
        else
            local rotated=()
            shopt -s nullglob
            rotated=("$src".*)
            shopt -u nullglob
            if (( ${#rotated[@]} )); then
                zcat -f -- "${rotated[@]}" 2>/dev/null || true
            fi
            cat -- "$src"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_jails() {
    require_fail2ban
    local jail bantime maxretry findtime total=0 count
    heading "Jails"
    printf '%-22s %8s %10s %9s %9s\n' "JAIL" "BANNED" "BANTIME" "FINDTIME" "MAXRETRY"
    printf '%s\n' "$(printf '%.0s-' {1..62})"
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        count="$(get_banned "$jail" | wc -l | tr -d ' ')"
        bantime="$(jail_prop "$jail" bantime)"
        findtime="$(jail_prop "$jail" findtime)"
        maxretry="$(jail_prop "$jail" maxretry)"
        total=$(( total + count ))
        printf '%-22s %8s %10s %9s %9s\n' \
            "$jail" "$count" "${bantime:-?}" "${findtime:-?}" "${maxretry:-?}"
    done < <(get_jails)
    printf '%s\n' "$(printf '%.0s-' {1..62})"
    printf '%-22s %8s\n' "TOTAL" "$total"
}

cmd_list() {
    require_fail2ban
    local filter_jail="${1:-}"
    local jail ip count grand=0
    local -a _ips=()

    [[ -z $filter_jail ]] || assert_jail "$filter_jail"

    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        [[ -z $filter_jail || $jail == "$filter_jail" ]] || continue

        mapfile -t _ips < <(get_banned "$jail")
        count=${#_ips[@]}
        grand=$(( grand + count ))

        heading "$jail ${C_DIM}($count banned)${C_RESET}"
        if (( count == 0 )); then
            printf '  %s(none)%s\n' "$C_DIM" "$C_RESET"
            continue
        fi
        for ip in "${_ips[@]}"; do
            printf '  %s\n' "$ip"
        done
    done < <(get_jails)

    printf '\n%sTotal banned across listed jails: %s%s\n' "$C_BOLD" "$grand" "$C_RESET"
}

cmd_ban() {
    require_root ban "$@"
    require_fail2ban
    local ip="${1:-}"; shift || true
    [[ -n $ip ]] || die "usage: $PROG ban <ip> [jail ...]   (omit jail to ban in all jails)"
    assert_ip "$ip"

    local -a targets=()
    if (( $# > 0 )); then
        local j
        for j in "$@"; do
            assert_jail "$j"
            targets+=("$j")
        done
    else
        mapfile -t targets < <(get_jails)
    fi

    (( ${#targets[@]} )) || die "no jails configured"

    local jail rc=0
    for jail in "${targets[@]}"; do
        if fail2ban-client set "$jail" banip "$ip" >/dev/null 2>&1; then
            log_ok "banned $ip in $jail"
        else
            log_warn "failed to ban $ip in $jail (already banned?)"
            rc=1
            SOFT_FAIL=1
        fi
    done
    return $rc
}

cmd_unban() {
    require_root unban "$@"
    require_fail2ban
    local ip="${1:-}"; shift || true
    [[ -n $ip ]] || die "usage: $PROG unban <ip> [jail ...]   (omit jail to unban everywhere)"
    assert_ip "$ip"

    local -a targets=()
    if (( $# > 0 )); then
        local j
        for j in "$@"; do
            assert_jail "$j"
            targets+=("$j")
        done
    else
        mapfile -t targets < <(get_jails)
    fi

    local jail found=0
    for jail in "${targets[@]}"; do
        if get_banned "$jail" | grep -qxF "$ip"; then
            if fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1; then
                log_ok "unbanned $ip from $jail"
                found=1
            else
                log_err "unban failed for $ip in $jail"
            fi
        fi
    done

    if (( found == 0 )); then
        log_warn "$ip was not banned in any of the checked jails"
        SOFT_FAIL=1
        return 1
    fi
}

cmd_unban_all() {
    require_root unban-all "$@"
    require_fail2ban
    local jail_arg="${1:-}"
    local -a targets=()

    if [[ -n $jail_arg ]]; then
        assert_jail "$jail_arg"
        targets=("$jail_arg")
    else
        mapfile -t targets < <(get_jails)
    fi

    local total=0 jail
    for jail in "${targets[@]}"; do
        total=$(( total + $(get_banned "$jail" | wc -l | tr -d ' ') ))
    done

    (( total > 0 )) || { log_info "nothing to unban"; return 0; }

    printf '%sThis will unban %s address(es) across %s jail(s).%s\n' \
        "$C_YELLOW" "$total" "${#targets[@]}" "$C_RESET"
    read -r -p "Type 'yes' to confirm: " confirm
    [[ $confirm == "yes" ]] || { log_info "cancelled"; return 0; }

    local ip
    for jail in "${targets[@]}"; do
        while IFS= read -r ip; do
            [[ -n $ip ]] || continue
            if fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1; then
                printf '  unbanned %s from %s\n' "$ip" "$jail"
            else
                log_warn "  failed: $ip in $jail"
            fi
        done < <(get_banned "$jail")
    done
    log_ok "done"
}

cmd_check() {
    require_fail2ban
    local ip="${1:-}"
    [[ -n $ip ]] || die "usage: $PROG check <ip>"
    assert_ip "$ip"

    local jail hits=0
    heading "Ban status for $ip"
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        if get_banned "$jail" | grep -qxF "$ip"; then
            printf '  %sBANNED%s in %s\n' "$C_RED" "$C_RESET" "$jail"
            hits=$(( hits + 1 ))
        fi
    done < <(get_jails)

    (( hits > 0 )) || printf '  %snot banned in any jail%s\n' "$C_GREEN" "$C_RESET"

    heading "Recent log activity"
    local matches
    matches="$(read_log 0 | grep -F -- "$ip" | tail -20 || true)"
    if [[ -n $matches ]]; then
        printf '%s\n' "$matches" | sed 's/^/  /'
    else
        printf '  %sno log entries found%s\n' "$C_DIM" "$C_RESET"
    fi
}

cmd_top() {
    require_fail2ban
    local n="${1:-15}"
    [[ $n =~ ^[0-9]+$ ]] || die "usage: $PROG top [count]"

    heading "Top $n banned addresses (all time, from logs)"
    local out
    out="$(read_log 0 \
        | grep -E '\] Ban ' \
        | awk '{print $NF}' \
        | sort | uniq -c | sort -rn | head -n "$n" || true)"

    if [[ -z $out ]]; then
        printf '  %sno ban events found in the log%s\n' "$C_DIM" "$C_RESET"
        return 0
    fi
    printf '%8s  %s\n' "BANS" "IP"
    # Explicit IFS: the global IFS excludes spaces, which would break splitting.
    printf '%s\n' "$out" | while IFS=' ' read -r count ip; do
        printf '%8s  %s\n' "$count" "$ip"
    done
}

cmd_recent() {
    require_fail2ban
    local n="${1:-25}"
    [[ $n =~ ^[0-9]+$ ]] || die "usage: $PROG recent [count]"
    heading "Last $n ban/unban events"
    read_log 0 \
        | grep -E '\] (Ban|Unban) ' \
        | tail -n "$n" \
        | sed 's/^/  /' || printf '  %snone%s\n' "$C_DIM" "$C_RESET"
}

cmd_watch() {
    require_fail2ban
    log_info "Watching fail2ban activity. Ctrl-C to stop."
    local src
    src="$(resolve_logfile)"
    if [[ $src == "journal" ]]; then
        journalctl -u fail2ban -f --no-pager
    else
        tail -f "$src"
    fi
}

cmd_whitelist() {
    require_root whitelist "$@"
    require_fail2ban
    local ip="${1:-}"
    [[ -n $ip ]] || die "usage: $PROG whitelist <ip|cidr>"
    assert_ip "$ip"

    if [[ ! -f $IGNORE_DROPIN ]]; then
        install -m 0644 -o root -g root /dev/null "$IGNORE_DROPIN"
        cat > "$IGNORE_DROPIN" <<'EOF'
# Managed by f2b. Entries appended by `f2b whitelist <ip>`.
# Safe to edit by hand; keep the [DEFAULT] header and one ignoreip line.
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
EOF
    fi

    if grep -qF -- "$ip" "$IGNORE_DROPIN"; then
        log_warn "$ip is already whitelisted"
        return 0
    fi

    # Append to the existing ignoreip line rather than adding a second one.
    local tmp
    tmp="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    sed "s|^ignoreip = .*|& $ip|" "$IGNORE_DROPIN" > "$tmp"
    cat "$tmp" > "$IGNORE_DROPIN"

    log_ok "added $ip to $IGNORE_DROPIN"

    # Drop any live ban so the whitelist takes effect immediately.
    cmd_unban "$ip" >/dev/null 2>&1 || true

    log_info "reloading fail2ban to apply..."
    fail2ban-client reload >/dev/null && log_ok "reloaded"
}

cmd_unwhitelist() {
    require_root unwhitelist "$@"
    local ip="${1:-}"
    [[ -n $ip ]] || die "usage: $PROG unwhitelist <ip|cidr>"
    assert_ip "$ip"
    [[ -f $IGNORE_DROPIN ]] || die "no managed whitelist file at $IGNORE_DROPIN"

    grep -qF -- "$ip" "$IGNORE_DROPIN" || die "$ip is not in the managed whitelist"

    local tmp
    tmp="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    # Remove the token with its leading space, leaving the rest of the line intact.
    sed "s| ${ip//./\\.}\b||g" "$IGNORE_DROPIN" > "$tmp"
    cat "$tmp" > "$IGNORE_DROPIN"

    log_ok "removed $ip from the whitelist"
    fail2ban-client reload >/dev/null && log_ok "reloaded"
}

cmd_whitelist_show() {
    if [[ -f $IGNORE_DROPIN ]]; then
        heading "Managed whitelist ($IGNORE_DROPIN)"
        grep '^ignoreip' "$IGNORE_DROPIN" | sed 's/^ignoreip = //' | tr ' ' '\n' | sed 's/^/  /'
    else
        log_info "no managed whitelist file yet"
    fi
    heading "Effective ignoreip per jail"
    local jail
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        printf '  %-20s %s\n' "$jail" "$(jail_prop "$jail" ignoreip)"
    done < <(get_jails)
}

cmd_test() {
    local logpath="${1:-}" filter="${2:-}"
    [[ -n $logpath && -n $filter ]] \
        || die "usage: $PROG test <logfile> <filter>    e.g. $PROG test /var/log/auth.log sshd"
    [[ -r $logpath ]] || die "cannot read $logpath"
    command -v fail2ban-regex >/dev/null 2>&1 || die "fail2ban-regex not found"
    fail2ban-regex "$logpath" "$filter" --print-all-matched | tail -40
}

cmd_export() {
    require_fail2ban
    local jail ip first_jail=1 first_ip
    printf '{\n  "host": "%s",\n  "generated_at": "%s",\n  "jails": {\n' \
        "$(hostname -f 2>/dev/null || hostname)" "$(date -Iseconds)"
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        (( first_jail )) || printf ',\n'
        first_jail=0
        printf '    "%s": [' "$jail"
        first_ip=1
        while IFS= read -r ip; do
            [[ -n $ip ]] || continue
            (( first_ip )) || printf ', '
            first_ip=0
            printf '"%s"' "$ip"
        done < <(get_banned "$jail")
        printf ']'
    done < <(get_jails)
    printf '\n  }\n}\n'
}

cmd_reload() {
    require_root reload
    require_fail2ban
    log_info "reloading fail2ban configuration..."
    fail2ban-client reload && log_ok "reloaded"
}

cmd_status() {
    require_fail2ban
    heading "Service"
    systemctl is-active fail2ban >/dev/null 2>&1 \
        && printf '  fail2ban: %sactive%s\n' "$C_GREEN" "$C_RESET" \
        || printf '  fail2ban: %sinactive%s\n' "$C_RED" "$C_RESET"
    printf '  version : %s\n' "$(fail2ban-client version 2>/dev/null || echo unknown)"
    printf '  logtarget: %s\n' "$(resolve_logfile)"
    cmd_jails
}

cmd_menu() {
    require_fail2ban
    local choice ip jail
    while true; do
        heading "f2b interactive"
        cat <<'EOF'
  1) Status overview
  2) List banned IPs (all jails)
  3) List banned IPs (one jail)
  4) Ban an IP
  5) Unban an IP
  6) Check an IP
  7) Recent ban events
  8) Top offenders
  9) Whitelist an IP
 10) Watch live log
  q) Quit
EOF
        read -r -p "> " choice
        SOFT_FAIL=0
        case "$choice" in
            1) cmd_status ;;
            2) cmd_list ;;
            3) read -r -p "jail: " jail; cmd_list "$jail" || true ;;
            4) read -r -p "ip: " ip; read -r -p "jail (blank = all): " jail
               if [[ -n $jail ]]; then cmd_ban "$ip" "$jail" || true; else cmd_ban "$ip" || true; fi ;;
            5) read -r -p "ip: " ip; cmd_unban "$ip" || true ;;
            6) read -r -p "ip: " ip; cmd_check "$ip" || true ;;
            7) cmd_recent ;;
            8) cmd_top ;;
            9) read -r -p "ip: " ip; cmd_whitelist "$ip" || true ;;
            10) cmd_watch || true ;;
            q|Q) break ;;
            *) log_warn "unknown option" ;;
        esac
    done
}

usage() {
    cat <<EOF
${C_BOLD}$PROG${C_RESET} v$VERSION - friendlier fail2ban management

${C_BOLD}VIEWING${C_RESET}
  status                    Service state plus per-jail summary table
  jails                     Jail table: banned count, bantime, findtime, maxretry
  list [jail]               Banned IPs grouped by jail (all jails if omitted)
  check <ip>                Is this IP banned, and what does the log say
  recent [n]                Last n ban/unban events (default 25)
  top [n]                   Most-banned IPs all time (default 15)
  watch                     Follow fail2ban activity live
  export                    Dump all bans as JSON (for central collection)

${C_BOLD}ACTIONS${C_RESET}                                            ${C_DIM}(need root)${C_RESET}
  ban <ip> [jail ...]       Ban an IP. No jail given = every jail
  unban <ip> [jail ...]     Unban an IP. No jail given = every jail
  unban-all [jail]          Flush all bans, with confirmation
  reload                    Reload fail2ban config

${C_BOLD}WHITELIST${C_RESET}                                          ${C_DIM}(need root)${C_RESET}
  whitelist <ip|cidr>       Add to managed ignoreip drop-in and unban now
  unwhitelist <ip|cidr>     Remove from the managed drop-in
  whitelist-show            Show managed and effective ignoreip

${C_BOLD}OTHER${C_RESET}
  test <logfile> <filter>   Dry-run a filter with fail2ban-regex
  menu                      Interactive mode
  help                      This text

${C_BOLD}EXAMPLES${C_RESET}
  $PROG list sshd
  $PROG ban 203.0.113.9 sshd nginx-limit-req
  $PROG unban 203.0.113.9
  $PROG whitelist 10.10.0.0/16
  $PROG export > /var/backups/f2b-\$(date +%F).json
EOF
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
main() {
    local cmd="${1:-help}"
    shift || true
    case "$cmd" in
        status)          cmd_status "$@" ;;
        jails)           cmd_jails "$@" ;;
        list|ls)         cmd_list "$@" ;;
        check)           cmd_check "$@" ;;
        recent)          cmd_recent "$@" ;;
        top)             cmd_top "$@" ;;
        watch|tail)      cmd_watch "$@" ;;
        export)          cmd_export "$@" ;;
        ban)             cmd_ban "$@" ;;
        unban)           cmd_unban "$@" ;;
        unban-all)       cmd_unban_all "$@" ;;
        reload)          cmd_reload "$@" ;;
        whitelist)       cmd_whitelist "$@" ;;
        unwhitelist)     cmd_unwhitelist "$@" ;;
        whitelist-show)  cmd_whitelist_show "$@" ;;
        test)            cmd_test "$@" ;;
        menu)            cmd_menu "$@" ;;
        version|-v|--version) printf '%s %s\n' "$PROG" "$VERSION" ;;
        help|-h|--help)  usage ;;
        *)               log_err "unknown command: $cmd"; usage; exit 2 ;;
    esac
}

main "$@"