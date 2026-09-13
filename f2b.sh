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
readonly VERSION="1.1.0"

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
    readonly C_BLUE=$'\033[34m'
    readonly C_MAGENTA=$'\033[35m'
    readonly C_INV=$'\033[7m'
else
    readonly C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN=''
    readonly C_BLUE='' C_MAGENTA='' C_INV=''
fi

# Colour helpers for table cells.
# count_color <n>        -> red when > 0, green when 0
# duration_color <text>  -> red for "forever", plain otherwise
# Both accept padded input ("      12") so callers can align first.
count_color()    { local v="${1//[[:space:]]/}"; if [[ $v =~ ^[0-9]+$ ]] && (( v > 0 )); then printf '%s%s%s' "$C_RED$C_BOLD" "$1" "$C_RESET"; else printf '%s%s%s' "$C_GREEN" "$1" "$C_RESET"; fi; }
duration_color() { local v="${1//[[:space:]]/}"; if [[ $v == forever ]]; then printf '%s%s%s' "$C_RED" "$1" "$C_RESET"; else printf '%s' "$1"; fi; }
rule()           { printf '%s%s%s\n' "$C_DIM" "$(printf '%.0s─' $(seq 1 "${1:-62}"))" "$C_RESET"; }


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

# Formats a fail2ban duration given in seconds:
#   < 60s      -> "45s"
#   < 1 hour   -> "10m" or "1m30s"
#   >= 1 hour  -> "1h", "1h30m", "24h"
#   negative   -> "forever"     non-numeric -> passed through
fmt_duration() {
    local sec="${1:-}" h m r
    [[ $sec =~ ^-?[0-9]+$ ]] || { printf '%s\n' "${sec:-?}"; return 0; }
    if (( sec < 0 )); then
        printf 'forever\n'
    elif (( sec < 60 )); then
        printf '%ds\n' "$sec"
    elif (( sec < 3600 )); then
        m=$(( sec / 60 )); r=$(( sec % 60 ))
        if (( r == 0 )); then printf '%dm\n' "$m"; else printf '%dm%ds\n' "$m" "$r"; fi
    else
        h=$(( sec / 3600 )); m=$(( (sec % 3600) / 60 ))
        if (( m == 0 )); then printf '%dh\n' "$h"; else printf '%dh%dm\n' "$h" "$m"; fi
    fi
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

# Adds colour to fail2ban log lines on stdin: timestamps dim, [jail] cyan,
# "Ban" red, "Unban"/"Restore Ban" green, Found yellow, WARNING/ERROR red.
# Passes lines through untouched when colour is off. Unbuffered so it works
# on a live tail.
colorize_log() {
    [[ -n $C_RESET ]] || { cat; return 0; }
    local line
    while IFS= read -r line; do
        line="${line//\[NOTICE\]/$'\e[2m'[NOTICE]$'\e[0m'}"
        line="$(printf '%s' "$line" | sed -E \
            -e "s/^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:,]+)/${C_DIM}\\1${C_RESET}/" \
            -e "s/(\[[a-zA-Z0-9_.-]+\]) (Unban|Restore Ban) /${C_CYAN}\\1${C_RESET} ${C_GREEN}\\2${C_RESET} /" \
            -e "s/(\[[a-zA-Z0-9_.-]+\]) (Ban) /${C_CYAN}\\1${C_RESET} ${C_RED}${C_BOLD}\\2${C_RESET} /" \
            -e "s/(\[[a-zA-Z0-9_.-]+\]) (Found) /${C_CYAN}\\1${C_RESET} ${C_YELLOW}\\2${C_RESET} /" \
            -e "s/ (WARNING|ERROR|CRITICAL) / ${C_RED}\\1${C_RESET} /")"
        printf '%s\n' "$line"
    done
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_jails() {
    require_fail2ban
    local jail bantime maxretry findtime total=0 count
    heading "Jails"
    printf '%s%-22s %8s %10s %9s %9s%s\n' "$C_BOLD$C_DIM" "JAIL" "BANNED" "BANTIME" "FINDTIME" "MAXRETRY" "$C_RESET"
    rule 62
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        count="$(get_banned "$jail" | wc -l | tr -d ' ')"
        bantime="$(fmt_duration "$(jail_prop "$jail" bantime)")"
        findtime="$(fmt_duration "$(jail_prop "$jail" findtime)")"
        maxretry="$(jail_prop "$jail" maxretry)"
        total=$(( total + count ))
        # Colour codes have zero width, so pad the plain text first.
        printf '%s%-22s%s %s %s %s %9s\n' \
            "$C_CYAN" "$jail" "$C_RESET" \
            "$(count_color "$(printf '%8s' "$count")")" \
            "$(duration_color "$(printf '%10s' "${bantime:-?}")")" \
            "$(duration_color "$(printf '%9s' "${findtime:-?}")")" \
            "${maxretry:-?}"
    done < <(get_jails)
    rule 62
    printf '%s%-22s%s %s\n' "$C_BOLD" "TOTAL" "$C_RESET" "$(count_color "$(printf '%8s' "$total")")"
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
            printf '  %s●%s %s\n' "$C_RED" "$C_RESET" "$ip"
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
                printf '  %s✔%s unbanned %s from %s%s%s\n' "$C_GREEN" "$C_RESET" "$ip" "$C_CYAN" "$jail" "$C_RESET"
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
            printf '  %sBANNED%s in %s%s%s\n' "$C_RED$C_BOLD" "$C_RESET" "$C_CYAN" "$jail" "$C_RESET"
            hits=$(( hits + 1 ))
        fi
    done < <(get_jails)

    (( hits > 0 )) || printf '  %snot banned in any jail%s\n' "$C_GREEN" "$C_RESET"

    heading "Recent log activity"
    local matches
    matches="$(read_log 0 | grep -F -- "$ip" | tail -20 || true)"
    if [[ -n $matches ]]; then
        printf '%s\n' "$matches" | colorize_log | sed 's/^/  /'
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
    printf '%s%8s  %s%s\n' "$C_BOLD$C_DIM" "BANS" "IP" "$C_RESET"
    # Explicit IFS: the global IFS excludes spaces, which would break splitting.
    local color
    printf '%s\n' "$out" | while IFS=' ' read -r count ip; do
        if (( count >= 10 )); then color="$C_RED$C_BOLD"
        elif (( count >= 3 )); then color="$C_YELLOW"
        else color=""; fi
        printf '%s%8s%s  %s\n' "$color" "$count" "$C_RESET" "$ip"
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
        | colorize_log \
        | sed 's/^/  /' || printf '  %snone%s\n' "$C_DIM" "$C_RESET"
}

cmd_watch() {
    require_fail2ban
    log_info "Watching fail2ban activity. Ctrl-C to stop."
    local src
    src="$(resolve_logfile)"
    if [[ $src == "journal" ]]; then
        journalctl -u fail2ban -f --no-pager | colorize_log
    else
        tail -f "$src" | colorize_log
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

    if grep -qwF -- "$ip" "$IGNORE_DROPIN"; then
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

    grep -qwF -- "$ip" "$IGNORE_DROPIN" || die "$ip is not in the managed whitelist"

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
        grep '^ignoreip' "$IGNORE_DROPIN" | sed 's/^ignoreip = //' | tr ' ' '\n' \
            | sed "s/^/  ${C_GREEN}✔${C_RESET} /"
    else
        log_info "no managed whitelist file yet"
    fi
    heading "Effective ignoreip per jail"
    local jail
    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        printf '  %s%-20s%s %s%s%s\n' "$C_CYAN" "$jail" "$C_RESET" "$C_DIM" "$(jail_prop "$jail" ignoreip)" "$C_RESET"
    done < <(get_jails)
}

cmd_test() {
    local logpath="${1:-}" filter="${2:-}"
    [[ -n $logpath && -n $filter ]] \
        || die "usage: $PROG test <logfile> <filter>    e.g. $PROG test /var/log/auth.log sshd"
    [[ -r $logpath ]] || die "cannot read $logpath"
    command -v fail2ban-regex >/dev/null 2>&1 || die "fail2ban-regex not found"
    fail2ban-regex "$logpath" "$filter" --print-all-matched | tail -40 \
        || { SOFT_FAIL=1; log_warn "fail2ban-regex exited non-zero (no matches?)"; return 1; }
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
        && printf '  %-10s %s● active%s\n' "fail2ban" "$C_GREEN$C_BOLD" "$C_RESET" \
        || printf '  %-10s %s● inactive%s\n' "fail2ban" "$C_RED$C_BOLD" "$C_RESET"
    printf '  %-10s %s\n' "version" "$(fail2ban-client version 2>/dev/null || echo unknown)"
    printf '  %-10s %s%s%s\n' "logtarget" "$C_DIM" "$(resolve_logfile)" "$C_RESET"
    cmd_jails
}

# ---------------------------------------------------------------------------
# Interactive TUI (pure bash: arrow keys, scrolling lists, alt screen)
# ---------------------------------------------------------------------------
#
# Menu item syntax (tui_menu):
#   "Label"                 selectable
#   "Label<TAB>description" selectable, description drawn dim in a 2nd column
#   "#Section"              non-selectable section header
# TUI_CHOICE is the index among *selectable* items only, so callers can add
# or move section headers without renumbering their case statements.

TUI_CHOICE=-1
TUI_CURSOR=0
TUI_KEY=""
TUI_HDR=""           # cached dashboard block
TUI_HDR_ROWS=0
TUI_ACTIVE=0
TUI_RESIZED=0
TUI_COLS=80
TUI_ROWS=24
TUI_JAIL=""

tput_q() { tput "$@" 2>/dev/null || true; }

tui_size() {
    TUI_COLS="$(tput cols 2>/dev/null || echo 80)"
    TUI_ROWS="$(tput lines 2>/dev/null || echo 24)"
    (( TUI_COLS >= 40 )) || TUI_COLS=40
}

tui_enter() {
    TUI_ACTIVE=1
    tput_q smcup
    tput_q civis
    trap 'tui_leave; exit 130' INT TERM
    trap 'tui_leave' EXIT
    trap 'TUI_RESIZED=1' WINCH
    tui_size
}

tui_leave() {
    (( TUI_ACTIVE )) || return 0
    TUI_ACTIVE=0
    tput_q cnorm
    tput_q sgr0
    tput_q rmcup
}

# Repeats $1 $2 times.
rep() { local s="$1" n="$2" out=""; while (( n-- > 0 )); do out+="$s"; done; printf '%s' "$out"; }

# Truncates $1 to $2 visible characters (input must be free of escapes).
clip() { local s="$1" w="$2"; (( ${#s} > w )) && s="${s:0:w-1}…"; printf '%s' "$s"; }

# Reads one keypress into TUI_KEY as a symbolic name. Returns 1 on EOF and 2
# on timeout; the timeout lets menus notice a terminal resize without a key.
tui_key() {
    local k rest more rc=0
    TUI_KEY=""
    IFS= read -rsn1 -t 0.5 k || rc=$?
    (( rc > 128 )) && return 2
    (( rc == 0 )) || return 1
    if [[ $k == $'\e' ]]; then
        IFS= read -rsn2 -t 0.05 rest || true
        k+="$rest"
        if [[ $rest =~ ^\[[0-9]$ ]]; then
            IFS= read -rsn1 -t 0.05 more || true
            k+="$more"
        fi
    fi
    case "$k" in
        $'\e[A'|k)          TUI_KEY=up ;;
        $'\e[B'|j)          TUI_KEY=down ;;
        $'\e[C'|l)          TUI_KEY=right ;;
        $'\e[D'|h)          TUI_KEY=left ;;
        $'\e[H'|$'\e[1~'|g) TUI_KEY=home ;;
        $'\e[F'|$'\e[4~'|G) TUI_KEY=end ;;
        $'\e[5~')           TUI_KEY=pgup ;;
        $'\e[6~')           TUI_KEY=pgdn ;;
        ''|$'\n'|' ')       TUI_KEY=enter ;;
        $'\e'|q|Q)          TUI_KEY=quit ;;
        r|R)                TUI_KEY=refresh ;;
        *)                  TUI_KEY="char:$k" ;;
    esac
}

# Builds the boxed dashboard. Called once per screen, not per keypress,
# because it talks to fail2ban.
tui_refresh_header() {
    local svc svc_plain jail n jails=0 banned=0 who who_plain summary="" inner line1 line2 line3 pad
    tui_size
    inner=$(( TUI_COLS - 4 ))

    if systemctl is-active fail2ban >/dev/null 2>&1; then
        svc="${C_GREEN}● active${C_RESET}";  svc_plain="● active"
    else
        svc="${C_RED}● inactive${C_RESET}";  svc_plain="● inactive"
    fi
    if (( EUID == 0 )); then
        who="${C_GREEN}root${C_RESET}"; who_plain="root"
    else
        who="${C_YELLOW}read-only · run with sudo to ban/unban${C_RESET}"
        who_plain="read-only · run with sudo to ban/unban"
    fi

    while IFS= read -r jail; do
        [[ -n $jail ]] || continue
        n="$(get_banned "$jail" | wc -l | tr -d ' ')"
        jails=$(( jails + 1 )); banned=$(( banned + n ))
        summary+="${summary:+  }${jail} ${n}"
    done < <(get_jails)
    [[ -n $summary ]] || summary="no jails configured"

    # Line 1: name + host left, user right.
    local l="$PROG v$VERSION  ·  $(hostname 2>/dev/null || true)"
    pad=$(( inner - ${#l} - ${#who_plain} ))
    (( pad >= 2 )) || { who="${C_YELLOW}$(clip "$who_plain" $(( inner - ${#l} - 2 )))${C_RESET}"; pad=2; }
    line1="${C_BOLD}${C_CYAN}${PROG}${C_RESET} v${VERSION}  ${C_DIM}·  $(hostname 2>/dev/null || true)${C_RESET}$(rep ' ' "$pad")${who}"

    # Line 2: service, jails, bans.
    local l2p="fail2ban ${svc_plain}   ${jails} jails   ${banned} banned"
    line2="fail2ban ${svc}   ${C_BOLD}${jails}${C_RESET} jails   ${C_BOLD}${banned}${C_RESET} banned$(rep ' ' $(( inner - ${#l2p} )))"

    # Line 3: per-jail counts.
    local s3; s3="$(clip "$summary" "$inner")"
    line3="${C_DIM}${s3}${C_RESET}$(rep ' ' $(( inner - ${#s3} )))"

    TUI_HDR="${C_DIM}╭$(rep '─' $(( TUI_COLS - 2 )))╮${C_RESET}"$'\n'
    TUI_HDR+="${C_DIM}│${C_RESET} ${line1} ${C_DIM}│${C_RESET}"$'\n'
    TUI_HDR+="${C_DIM}│${C_RESET} ${line2} ${C_DIM}│${C_RESET}"$'\n'
    TUI_HDR+="${C_DIM}│${C_RESET} ${line3} ${C_DIM}│${C_RESET}"$'\n'
    TUI_HDR+="${C_DIM}╰$(rep '─' $(( TUI_COLS - 2 )))╯${C_RESET}"
    TUI_HDR_ROWS=5
}

tui_draw_header() {
    tput_q clear
    printf '%s\n' "$TUI_HDR"
}

# Draws header + a breadcrumb-style screen title.
tui_screen() {
    tui_draw_header
    printf ' %s%s%s\n\n' "$C_BOLD" "$1" "$C_RESET"
}

# Footer with keycap-style hints: tui_hints "↑↓" "move" "Enter" "select" ...
# Hints that would not fit on one line are dropped from the right.
tui_hints() {
    local out="" used=1 need
    while (( $# >= 2 )); do
        need=$(( ${#1} + ${#2} + 6 ))
        (( used + need <= TUI_COLS )) || break
        out+="${C_INV} $1 ${C_RESET}${C_DIM} $2${C_RESET}   "
        used=$(( used + need ))
        shift 2
    done
    printf ' %s\n' "$out"
}

# tui_menu <title> <item>...   -> TUI_CHOICE = selectable index, -1 on back
tui_menu() {
    local title="$1"; shift
    local -a items=("$@") sel=() labels=() descs=()
    local i n=0 labelw=0 cur=${TUI_CURSOR:-0} top=0 row vis key num lab desc line plain width

    for i in "${!items[@]}"; do
        if [[ ${items[i]} == '#'* ]]; then
            labels[i]="${items[i]#\#}"; descs[i]=""
        else
            sel+=("$i")
            labels[i]="${items[i]%%$'\t'*}"
            descs[i]=""; [[ ${items[i]} == *$'\t'* ]] && descs[i]="${items[i]#*$'\t'}"
            (( ${#labels[i]} > labelw )) && labelw=${#labels[i]}
        fi
    done
    n=${#sel[@]}
    (( n > 0 )) || { TUI_CHOICE=-1; return 0; }
    (( cur < n )) || cur=$(( n - 1 ))
    (( cur >= 0 )) || cur=0
    (( labelw <= 40 )) || labelw=40

    while true; do
        if (( TUI_RESIZED )); then TUI_RESIZED=0; tui_refresh_header; fi
        tui_size
        vis=$(( TUI_ROWS - TUI_HDR_ROWS - 6 ))
        (( vis >= 3 )) || vis=3
        width=$(( TUI_COLS - 2 ))
        row=${sel[cur]}
        (( row < top )) && top=$row
        (( row >= top + vis )) && top=$(( row - vis + 1 ))
        # Don't start a page on a header whose items are all above.
        (( top > 0 && top == row && row > 0 )) && [[ ${items[row-1]} == '#'* ]] && top=$(( top - 1 ))

        tui_draw_header
        printf ' %s%s%s' "$C_BOLD" "$title" "$C_RESET"
        (( ${#items[@]} > vis )) && printf '  %s%d/%d%s' "$C_DIM" "$(( cur + 1 ))" "$n" "$C_RESET"
        printf '\n\n'

        for (( i = top; i < ${#items[@]} && i < top + vis; i++ )); do
            if [[ ${items[i]} == '#'* ]]; then
                if [[ -z ${labels[i]} ]]; then
                    printf ' %s%s%s\n' "$C_DIM" "$(rep '─' $(( width - 2 )))" "$C_RESET"
                else
                    printf ' %s%s %s%s\n' "$C_DIM" "$(clip "${labels[i]}" $(( width - 6 )))" \
                        "$(rep '─' $(( width - ${#labels[i]} - 3 > 0 ? width - ${#labels[i]} - 3 : 0 )))" "$C_RESET"
                fi
                continue
            fi
            # selectable index of this row
            num=""; for (( key = 0; key < n; key++ )); do (( sel[key] == i )) && { num=$(( key + 1 )); break; }; done
            lab="$(clip "${labels[i]}" "$labelw")"
            desc="$(clip "${descs[i]}" $(( width - labelw - 8 > 0 ? width - labelw - 8 : 0 )))"
            printf -v plain '  %s  %-*s  %s' "$( (( num <= 9 )) && printf '%d' "$num" || printf ' ' )" "$labelw" "$lab" "$desc"
            plain="$(clip "$plain" "$width")"
            if (( i == sel[cur] )); then
                printf ' %s%s%s%s%s\n' "$C_INV$C_BOLD" "❯" "${plain:1}" "$(rep ' ' $(( width - ${#plain} - 1 )))" "$C_RESET"
            else
                printf ' %s%s%s%-*s  %s%s%s\n' "$C_DIM" "${plain:2:1}" "$C_RESET  " "$labelw" "$lab" "$C_DIM" "$desc" "$C_RESET"
            fi
        done
        for (( row = i - top; row < vis; row++ )); do printf '\n'; done

        printf '\n'
        tui_hints "↑↓" "move" "⏎" "select" "1-9" "jump" "r" "refresh" "q" "back"

        # Wait for a key; on timeout only redraw if the terminal was resized.
        while true; do
            key=0; tui_key || key=$?
            (( key == 0 )) && break
            (( key == 2 )) || { TUI_CHOICE=-1; return 0; }
            (( TUI_RESIZED )) && continue 2
        done
        case "$TUI_KEY" in
            up)    cur=$(( (cur - 1 + n) % n )) ;;
            down)  cur=$(( (cur + 1) % n )) ;;
            home)  cur=0 ;;
            end)   cur=$(( n - 1 )) ;;
            pgup)  cur=$(( cur - vis < 0 ? 0 : cur - vis )) ;;
            pgdn)  cur=$(( cur + vis >= n ? n - 1 : cur + vis )) ;;
            refresh) tui_refresh_header ;;
            enter|right) TUI_CHOICE=$cur; TUI_CURSOR=$cur; return 0 ;;
            quit|left)   TUI_CHOICE=-1; return 0 ;;
            char:[1-9])
                i=$(( ${TUI_KEY#char:} - 1 ))
                if (( i < n )); then TUI_CHOICE=$i; TUI_CURSOR=$i; return 0; fi ;;
        esac
    done
}

# tui_prompt <label> <varname> [default]  -> 1 if left blank/cancelled
tui_prompt() {
    local label="$1" __var="$2" default="${3:-}" value
    tput_q cnorm
    printf ' %sEsc/blank cancels%s\n\n' "$C_DIM" "$C_RESET"
    IFS= read -r -e -p "  ${C_BOLD}${label}${C_RESET}${default:+ ${C_DIM}[$default]${C_RESET}} ${C_CYAN}❯${C_RESET} " value || value=""
    tput_q civis
    value="${value//[[:space:]]/}"
    [[ -n $value ]] || value="$default"
    printf -v "$__var" '%s' "$value"
    [[ -n $value ]]
}

# tui_run <title> <command...>
# Runs the command in a subshell so die() only aborts the action, not the TUI,
# under a titled frame, then waits for a key. Ctrl-C during the action returns
# to the menu.
tui_run() {
    local title="$1"; shift
    tui_size
    tput_q clear
    printf '%s%s %s %s%s\n' "$C_BOLD$C_CYAN" "──" "$title" "$(rep '─' $(( TUI_COLS - ${#title} - 5 )))" "$C_RESET"
    tput_q cnorm
    trap ':' INT
    ( "$@" ) || true
    trap 'tui_leave; exit 130' INT
    tput_q civis
    printf '\n%s%s%s\n' "$C_DIM" "$(rep '─' "$TUI_COLS")" "$C_RESET"
    tui_hints "any key" "back to menu"
    IFS= read -rsn1 || true
}

tui_confirm() {
    local answer
    printf '\n  %s%s%s  %s[y/N]%s ' "$C_YELLOW" "$1" "$C_RESET" "$C_DIM" "$C_RESET"
    IFS= read -rsn1 answer || answer=""
    printf '\n'
    [[ $answer == [yY] ]]
}

# tui_pick_jail <title> [with_all]  -> TUI_JAIL ("" means all jails); 1 on cancel
tui_pick_jail() {
    local title="$1" with_all="${2:-0}" jail count total=0
    local -a jails=() labels=()
    mapfile -t jails < <(get_jails)
    (( ${#jails[@]} )) || { tui_run "$title" log_warn "no jails configured"; return 1; }
    for jail in "${jails[@]}"; do
        count="$(get_banned "$jail" | wc -l | tr -d ' ')"
        total=$(( total + count ))
        labels+=("${jail}"$'\t'"${count} banned   bantime $(fmt_duration "$(jail_prop "$jail" bantime)")")
    done
    (( with_all )) && labels=("All jails"$'\t'"${total} banned across ${#jails[@]} jails" "${labels[@]}")
    TUI_CURSOR=0
    tui_menu "$title  ›  select a jail" "${labels[@]}"
    (( TUI_CHOICE >= 0 )) || return 1
    if (( with_all )); then
        (( TUI_CHOICE == 0 )) && { TUI_JAIL=""; return 0; }
        TUI_JAIL="${jails[TUI_CHOICE - 1]}"
    else
        TUI_JAIL="${jails[TUI_CHOICE]}"
    fi
}

# Drill-down: jail -> banned IP -> action.
tui_browse() {
    local jail ip
    local -a ips=()
    while true; do
        tui_pick_jail "Browse bans" 0 || return 0
        jail="$TUI_JAIL"
        while true; do
            mapfile -t ips < <(get_banned "$jail")
            if (( ${#ips[@]} == 0 )); then
                tui_run "Browse bans › $jail" log_info "no banned addresses in $jail"
                break
            fi
            TUI_CURSOR=0
            tui_menu "Browse bans  ›  $jail  ›  ${#ips[@]} banned" "${ips[@]}"
            (( TUI_CHOICE >= 0 )) || break
            ip="${ips[TUI_CHOICE]}"
            TUI_CURSOR=0
            tui_menu "Browse bans  ›  $jail  ›  $ip" \
                "Unban here"$'\t'"remove the ban in $jail only" \
                "Unban everywhere"$'\t'"remove the ban from every jail" \
                "Whitelist"$'\t'"add to ignoreip and unban (needs root)" \
                "Check"$'\t'"ban status in all jails and log history" \
                "Back"
            case $TUI_CHOICE in
                0) tui_run "Unban $ip from $jail" cmd_unban "$ip" "$jail" ;;
                1) tui_run "Unban $ip everywhere" cmd_unban "$ip" ;;
                2) tui_run "Whitelist $ip" cmd_whitelist "$ip" ;;
                3) tui_run "Check $ip" cmd_check "$ip" ;;
            esac
        done
    done
}

# tui_ip_action <title> <label> <command>   (ban / unban share this flow)
tui_ip_action() {
    local title="$1" label="$2" cmd="$3" ip
    tui_screen "$title"
    tui_prompt "$label" ip || return 0
    valid_ip "$ip" || { tui_run "$title" log_err "'$ip' is not a valid IPv4/IPv6 address or CIDR"; return 0; }
    tui_pick_jail "$title $ip" 1 || return 0
    if [[ -n $TUI_JAIL ]]; then
        tui_run "$title $ip in $TUI_JAIL" "$cmd" "$ip" "$TUI_JAIL"
    else
        tui_run "$title $ip in all jails" "$cmd" "$ip"
    fi
}

tui_action_check() {
    local ip
    tui_screen "Check an IP"
    tui_prompt "IP address" ip || return 0
    tui_run "Check $ip" cmd_check "$ip"
}

tui_action_whitelist() {
    local ip
    while true; do
        TUI_CURSOR=0
        tui_menu "Whitelist" \
            "Show"$'\t'"managed drop-in and effective ignoreip per jail" \
            "Add"$'\t'"whitelist an IP or CIDR and lift any live ban" \
            "Remove"$'\t'"drop an entry from the managed drop-in" \
            "Back"
        case $TUI_CHOICE in
            0) tui_run "Whitelist" cmd_whitelist_show ;;
            1) tui_screen "Whitelist  ›  add"
               tui_prompt "IP or CIDR" ip || continue
               tui_run "Whitelist $ip" cmd_whitelist "$ip" ;;
            2) tui_screen "Whitelist  ›  remove"
               tui_prompt "IP or CIDR" ip || continue
               tui_run "Unwhitelist $ip" cmd_unwhitelist "$ip" ;;
            *) return 0 ;;
        esac
    done
}

# tui_action_count <title> <label> <default> <command>
tui_action_count() {
    local title="$1" label="$2" default="$3" cmd="$4" n
    tui_screen "$title"
    tui_prompt "$label" n "$default" || return 0
    [[ $n =~ ^[0-9]+$ ]] || { tui_run "$title" log_err "'$n' is not a number"; return 0; }
    tui_run "$title ($n)" "$cmd" "$n"
}

cmd_tui() {
    require_fail2ban
    [[ -t 0 && -t 1 ]] || die "the interactive UI needs a terminal. Try: $PROG help"

    local main_cur=0
    local -a items=(
        "#View"
        "Status"$'\t'"service state and per-jail table"
        "Browse bans"$'\t'"jail › IP › unban / whitelist / check"
        "Check an IP"$'\t'"is it banned, and what the log says"
        "Recent events"$'\t'"latest ban/unban log lines"
        "Top offenders"$'\t'"most-banned addresses, all time"
        "Watch live"$'\t'"follow the fail2ban log (Ctrl-C to stop)"
        "#Actions  (root)"
        "Ban an IP"$'\t'"in one jail or all jails"
        "Unban an IP"$'\t'"in one jail or all jails"
        "Whitelist"$'\t'"show / add / remove ignoreip entries"
        "Reload"$'\t'"reload fail2ban configuration"
        "Flush bans"$'\t'"unban everything in one jail or all jails"
        "#"
        "Quit"
    )

    tui_enter
    tui_refresh_header
    while true; do
        SOFT_FAIL=0
        TUI_CURSOR=$main_cur
        tui_menu "Main menu" "${items[@]}"
        (( TUI_CHOICE >= 0 )) || break
        main_cur=$TUI_CHOICE
        case $TUI_CHOICE in
            0)  tui_run "Status" cmd_status ;;
            1)  tui_browse ;;
            2)  tui_action_check ;;
            3)  tui_action_count "Recent events" "How many events" 25 cmd_recent ;;
            4)  tui_action_count "Top offenders" "How many addresses" 15 cmd_top ;;
            5)  tui_run "Watch live" cmd_watch ;;
            6)  tui_ip_action "Ban" "IP or CIDR to ban" cmd_ban ;;
            7)  tui_ip_action "Unban" "IP to unban" cmd_unban ;;
            8)  tui_action_whitelist ;;
            9)  tui_screen "Reload"
                tui_confirm "Reload fail2ban configuration now?" && tui_run "Reload" cmd_reload ;;
            10) tui_pick_jail "Flush bans" 1 || continue
                if [[ -n $TUI_JAIL ]]; then
                    tui_run "Flush bans in $TUI_JAIL" cmd_unban_all "$TUI_JAIL"
                else
                    tui_run "Flush all bans" cmd_unban_all
                fi ;;
            11) break ;;
        esac
        tui_refresh_header
    done
    tui_leave
}

usage() {
    cat <<EOF
${C_BOLD}$PROG${C_RESET} v$VERSION - friendlier fail2ban management

${C_BOLD}${C_CYAN}VIEWING${C_RESET}
  ${C_GREEN}status${C_RESET}                    Service state plus per-jail summary table
  ${C_GREEN}jails${C_RESET}                     Jail table: banned count, bantime, findtime, maxretry
  ${C_GREEN}list${C_RESET} [jail]               Banned IPs grouped by jail (all jails if omitted)
  ${C_GREEN}check${C_RESET} <ip>                Is this IP banned, and what does the log say
  ${C_GREEN}recent${C_RESET} [n]                Last n ban/unban events (default 25)
  ${C_GREEN}top${C_RESET} [n]                   Most-banned IPs all time (default 15)
  ${C_GREEN}watch${C_RESET}                     Follow fail2ban activity live
  ${C_GREEN}export${C_RESET}                    Dump all bans as JSON (for central collection)

${C_BOLD}${C_CYAN}ACTIONS${C_RESET}                                            ${C_DIM}(need root)${C_RESET}
  ${C_GREEN}ban${C_RESET} <ip> [jail ...]       Ban an IP. No jail given = every jail
  ${C_GREEN}unban${C_RESET} <ip> [jail ...]     Unban an IP. No jail given = every jail
  ${C_GREEN}unban-all${C_RESET} [jail]          Flush all bans, with confirmation
  ${C_GREEN}reload${C_RESET}                    Reload fail2ban config

${C_BOLD}${C_CYAN}WHITELIST${C_RESET}                                          ${C_DIM}(need root)${C_RESET}
  ${C_GREEN}whitelist${C_RESET} <ip|cidr>       Add to managed ignoreip drop-in and unban now
  ${C_GREEN}unwhitelist${C_RESET} <ip|cidr>     Remove from the managed drop-in
  ${C_GREEN}whitelist-show${C_RESET}            Show managed and effective ignoreip

${C_BOLD}${C_CYAN}OTHER${C_RESET}
  ${C_GREEN}test${C_RESET} <logfile> <filter>   Dry-run a filter with fail2ban-regex
  ${C_GREEN}menu | tui${C_RESET}                Interactive terminal UI (default with no args)
  ${C_GREEN}help${C_RESET}                      This text (default when not on a terminal)

${C_BOLD}${C_CYAN}EXAMPLES${C_RESET}
  ${C_DIM}$PROG list sshd${C_RESET}
  ${C_DIM}$PROG ban 203.0.113.9 sshd nginx-limit-req${C_RESET}
  ${C_DIM}$PROG unban 203.0.113.9${C_RESET}
  ${C_DIM}$PROG whitelist 10.10.0.0/16${C_RESET}
  ${C_DIM}$PROG export > /var/backups/f2b-\$(date +%F).json${C_RESET}
EOF
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
main() {
    local cmd="${1:-}"
    if [[ -z $cmd ]]; then
        if [[ -t 0 && -t 1 ]]; then cmd=tui; else cmd=help; fi
    fi
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
        menu|tui|ui)     cmd_tui "$@" ;;
        version|-v|--version) printf '%s %s\n' "$PROG" "$VERSION" ;;
        help|-h|--help)  usage ;;
        *)               log_err "unknown command: $cmd"; usage; exit 2 ;;
    esac
}

main "$@"