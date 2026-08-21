#!/usr/bin/env bash
#
# ============================================================
# IP SECURITY INTELLIGENCE
# Version 6.4
#
# Sources:
#   - RDAP
#   - Reverse DNS
#   - WHOIS
#   - IPinfo
#   - Team Cymru IP-to-ASN (free, no key — authoritative ASN cross-check)
#   - VirusTotal
#   - AbuseIPDB
#   - GreyNoise Community / Authenticated
#   - AlienVault OTX
#   - Shodan InternetDB (free, no key — open ports/CVEs/tags)
#   - Spamhaus ZEN DNSBL (free, no key — passive blocklist check)
#   - SpamCop DNSBL (free, no key)
#   - Barracuda Reputation DNSBL (free, no key)
#
# Features:
#   - Parallel lookups
#   - Interactive multi-IP mode
#   - Single-IP mode
#   - Risk scoring with visual ASCII risk bar
#   - "Sources checked" at-a-glance status table
#   - Coloured terminal output
#   - Coloured TXT reports using ANSI escape sequences
#   - Styled standalone HTML dashboard report (new in 6.4)
#   - Complete registration information
#   - Investigation links
#   - GreyNoise Community lookup fixed
#
# Changes in 6.4:
#   - Every scan now also writes a self-contained, styled HTML report
#     alongside the existing TXT report (same basename, .html
#     extension) — a dark-themed dashboard with a risk gauge, a
#     sources-checked grid, findings, network/ownership table,
#     per-source intel cards, blocklist consensus, Shodan InternetDB
#     detail, investigation links, and the raw RDAP/WHOIS text.
#   - HTML generation is fully additive and best-effort: it reuses the
#     same in-memory values as the TXT report, never blocks or alters
#     the existing scan/score/TXT-report flow, and any failure to
#     build it only prints a warning — the TXT report and exit code
#     behavior are unchanged.
#   - All values are HTML-escaped via Python's html.escape before
#     being written out, so odd characters coming back from any API
#     (org names, hostnames, tags, etc.) can't break the page.
#
# Changes in 6.5:
#   - FIX: a local DNS resolver failure could leak error text (e.g.
#     ";; communications error to X#53: timed out") onto dig's stdout
#     even with stderr redirected. That text was previously trusted
#     as real data — turning a broken resolver into a false "listed"
#     verdict on Spamhaus/SpamCop/Barracuda (and a garbage PTR record)
#     for otherwise-clean IPs. Every dig result is now validated
#     (hostname format for reverse DNS, 127.0.0.x format for DNSBLs)
#     before it's trusted; anything else is reported as a failed
#     lookup, never as a false positive or false negative.
#   - New CLI: -h/--help, -V/--version, --no-color (also honours the
#     NO_COLOR env var), -o/--output-dir <dir>.
#   - New batch mode: -b/--batch <file> scans every IP in a file
#     (one per line, '#' comments allowed) and exits with the worst
#     severity code — usable from cron/CI against a watchlist.
#   - Console output now also shows the live "sources checked" grid
#     (previously only written to the report file) and a compact
#     one-line "at a glance" summary per scan.
#
# Changes in 6.6:
#   - Reports now live under two subdirectories instead of one flat
#     folder: <base>/text-reports/ and <base>/html-reports/.
#   - Reports are never written under /root. If this tool is invoked
#     as root (e.g. via sudo), it now auto-detects a real, existing
#     non-root user on the machine (preferring $SUDO_USER, falling
#     back to the first regular UID>=1000 account) and stores reports
#     under that user's home instead — and chowns the directories and
#     every report file it writes to that user, so files aren't left
#     root-owned and unreadable to the person who actually runs scans.
#     -o/--output-dir and $IPINTEL_REPORT_DIR still override this
#     entirely, same as before.
#
# Changes in 6.3:
#   - Added Team Cymru IP-to-ASN as a third, authoritative ASN source
#     (free, no key, single DNS/whois round trip) — used as a
#     cross-check and fallback ahead of the IPinfo-org regex guess
#   - Added SpamCop and Barracuda as two more free DNSBL blocklist
#     checks alongside Spamhaus; the report now shows blocklist
#     consensus (how many of the 3 lists flag the IP) instead of
#     a single yes/no
#   - Added a visual ASCII risk bar (e.g. [████████░░░░░░░░░░░░])
#     next to the numeric score, in both console and report
#   - Added a "SOURCES CHECKED" table at the top of every report so
#     it's immediately clear which of the 12 sources actually
#     returned data for this scan, instead of having to scan
#     through every section to find "NOT CONFIGURED" notes
#
# Changes in 6.2:
#   - Added Shodan InternetDB: passive, free, no-key lookup of open
#     ports, known CVEs, tags, hostnames and CPEs already observed
#     for the IP. Does not actively scan the target itself.
#   - Added Spamhaus ZEN DNSBL: free, no-key, passive reverse-DNS
#     blocklist check (the same mechanism mail servers use) that
#     flags known spam sources / compromised hosts / hijacked
#     netblocks. A listing now also triggers the malicious override.
#   - Both new sources feed into risk scoring and the malicious
#     override, and get their own report sections + console lines.
#   - Both are IPv4-only and cleanly marked "not applicable" for
#     IPv6 targets rather than silently failing.
#
# Changes in 6.1:
#   - Numeric fields from all APIs are sanitized before use in
#     arithmetic comparisons (prevents "integer expression expected"
#     crashes and silently-wrong scoring on malformed API responses)
#   - Any single confirmed-malicious indicator (VT malicious>0,
#     AbuseIPDB confidence >=75, GreyNoise=malicious) now force-
#     escalates that IP's severity to at least HIGH and prints a
#     standalone banner, instead of being diluted by the weighted score
#   - Global interrupt-safe cleanup of all temp directories (Ctrl-C mid
#     scan no longer leaks $TMP dirs)
#   - User input is trimmed before IP validation
#   - Session-level summary + final banner across all IPs scanned in
#     interactive mode, with an exit code that reflects the worst
#     outcome across the whole session
#
# ============================================================
set -u
set -o pipefail
VERSION="6.6"
# REPORT_DIR / TEXT_REPORT_DIR / HTML_REPORT_DIR are resolved further
# down (see resolve_report_base_dir, called after argument parsing),
# so -o/--output-dir or $IPINTEL_REPORT_DIR can override the
# auto-detected non-root user's home directory.
REPORT_DIR=""
TEXT_REPORT_DIR=""
HTML_REPORT_DIR=""
REPORT_DIR_OWNER=""
# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'
# ============================================================
# LOGGING FUNCTIONS
# ============================================================
info()    { echo -e "${BLUE}[*]${NC} $1"; }
ok()      { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
bad()     { echo -e "${RED}[-]${NC} $1"; }
finding() { echo -e "${CYAN}[FINDING]${NC} $1"; }
section() {
    local title="$1"
    local width=60
    local pad=$(( (width - ${#title}) / 2 ))
    [[ "$pad" -lt 0 ]] && pad=0
    echo
    printf '%b' "${BOLD}${CYAN}"
    printf '┌'; printf '─%.0s' $(seq 1 "$width"); printf '┐\n'
    printf '│%*s%s%*s│\n' "$pad" "" "$title" $((width - pad - ${#title})) ""
    printf '└'; printf '─%.0s' $(seq 1 "$width"); printf '┘\n'
    printf '%b' "${NC}"
}
# ============================================================
# REPORT DIRECTORY RESOLUTION
# Reports are never written under /root. If this tool is run as root
# (e.g. via sudo, common for whois/raw-socket-adjacent tools), it
# resolves an actual non-root user on the machine — preferring
# $SUDO_USER — and stores reports under that user's home instead, so
# a scan tool doesn't leave artifacts an ordinary user can't read
# without sudo. Sets the globals REPORT_DIR and REPORT_DIR_OWNER
# directly (NOT via stdout/echo) — this must be called directly, not
# as `x="$(resolve_report_base_dir)"`, since command substitution
# runs in a subshell and any variables it sets would be lost when
# the subshell exits.
# ============================================================
resolve_report_base_dir() {
    if [[ "$(id -u)" -ne 0 ]]; then
        REPORT_DIR="${HOME}/ip-intelligence-reports"
        REPORT_DIR_OWNER=""
        return 0
    fi
    # Running as root. Prefer the user who actually invoked sudo.
    local target_user="" target_home=""
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        target_user="$SUDO_USER"
    else
        # No sudo context — fall back to the first "real" human user
        # on the system: UID >= 1000 (standard Linux convention),
        # UID < 65534 (excludes 'nobody'), with a real login shell.
        target_user="$(
            awk -F: '($3 >= 1000 && $3 < 65534 && $1 != "nobody" && $7 !~ /(nologin|false)$/) {print $1; exit}' \
                /etc/passwd 2>/dev/null
        )"
    fi
    if [[ -n "$target_user" ]]; then
        target_home="$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)"
        [[ -z "$target_home" ]] && target_home="$(
            awk -F: -v u="$target_user" '$1 == u {print $6; exit}' /etc/passwd 2>/dev/null
        )"
    fi
    if [[ -n "$target_home" && -d "$target_home" ]]; then
        REPORT_DIR_OWNER="$target_user"
        REPORT_DIR="${target_home}/ip-intelligence-reports"
    else
        # Last resort: running as root with no other user account
        # findable anywhere on the machine. Reports still can't live
        # under /root, so they go to a shared, world-readable system
        # location instead — clearly flagged, since this is unusual.
        warn "Running as root and no non-root user account was found on this machine — reports will be saved under /var/lib/ip-intelligence-reports instead of a user's home."
        REPORT_DIR_OWNER=""
        REPORT_DIR="/var/lib/ip-intelligence-reports"
    fi
}
# ============================================================
# DEPENDENCIES
# ============================================================
for cmd in curl jq python3 dig whois timeout sed awk grep head xargs tr mktemp date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        bad "$cmd is not installed."
        echo
        echo "Install dependencies:"
        echo
        echo "apt update && apt install -y curl jq python3 dnsutils whois coreutils"
        echo
        exit 1
    fi
done
# ============================================================
# ARGUMENT PARSING
#
# Supports:
#   ip_intel.sh <ip>                  scan one IP and exit
#   ip_intel.sh -b/--batch <file>      scan every IP in a file, one per
#                                      line ('#' comments allowed), then
#                                      exit with the worst severity code
#   ip_intel.sh                       no args: interactive prompt loop
#   -o/--output-dir <dir>             override where reports are saved
#   --no-color                        disable ANSI colour (also honours
#                                      the NO_COLOR env var convention:
#                                      https://no-color.org/)
#   -h/--help                         usage and exit
#   -V/--version                      version and exit
# ============================================================
NO_COLOR_FLAG=0
[[ -n "${NO_COLOR:-}" ]] && NO_COLOR_FLAG=1
OUTPUT_DIR_OVERRIDE=""
BATCH_FILE=""
CLI_IP=""
print_usage() {
    cat <<USAGE
IP Security Intelligence — version $VERSION

Usage:
  $(basename "$0") <ip>                    Scan a single IP and exit
  $(basename "$0") -b, --batch <file>      Scan every IP listed in <file>
                                            (one per line, '#' comments OK)
  $(basename "$0")                         No arguments: interactive prompt

Options:
  -o, --output-dir <dir>   Base directory for reports; two subfolders
                            are created inside it: text-reports/ and
                            html-reports/
                            (default: an auto-detected non-root user's
                            home — never /root — or \$IPINTEL_REPORT_DIR
                            if set)
  --no-color                Disable ANSI colour in console output
  -h, --help                 Show this help and exit
  -V, --version               Show version and exit

Environment (optional API keys — free-tier sources work without any):
  VT_API_KEY, ABUSEIPDB_API_KEY, GREYNOISE_API_KEY, OTX_API_KEY, IPINFO_TOKEN

Exit code reflects the worst severity seen this session:
  0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = CRITICAL
USAGE
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -V|--version)
            echo "IP Security Intelligence version $VERSION"
            exit 0
            ;;
        --no-color)
            NO_COLOR_FLAG=1
            shift
            ;;
        -o|--output-dir)
            OUTPUT_DIR_OVERRIDE="${2:-}"
            if [[ -z "$OUTPUT_DIR_OVERRIDE" ]]; then
                bad "$1 requires a directory argument"
                exit 1
            fi
            shift 2
            ;;
        --output-dir=*)
            OUTPUT_DIR_OVERRIDE="${1#*=}"
            shift
            ;;
        -b|--batch)
            BATCH_FILE="${2:-}"
            if [[ -z "$BATCH_FILE" ]]; then
                bad "$1 requires a file argument"
                exit 1
            fi
            shift 2
            ;;
        --batch=*)
            BATCH_FILE="${1#*=}"
            shift
            ;;
        --)
            shift
            [[ -n "${1:-}" ]] && CLI_IP="$1"
            break
            ;;
        -*)
            bad "Unknown option: $1"
            echo "Run '$(basename "$0") --help' for usage." >&2
            exit 1
            ;;
        *)
            CLI_IP="$1"
            shift
            ;;
    esac
done
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''; BOLD=''; NC=''
fi
if [[ -n "$OUTPUT_DIR_OVERRIDE" ]]; then
    REPORT_DIR="$OUTPUT_DIR_OVERRIDE"
    REPORT_DIR_OWNER=""
elif [[ -n "${IPINTEL_REPORT_DIR:-}" ]]; then
    REPORT_DIR="$IPINTEL_REPORT_DIR"
    REPORT_DIR_OWNER=""
else
    resolve_report_base_dir
fi
TEXT_REPORT_DIR="${REPORT_DIR}/text-reports"
HTML_REPORT_DIR="${REPORT_DIR}/html-reports"
mkdir -p "$TEXT_REPORT_DIR" "$HTML_REPORT_DIR" || {
    echo "Cannot create report directories under: $REPORT_DIR" >&2
    exit 1
}
if [[ -n "$REPORT_DIR_OWNER" ]]; then
    chown -R "${REPORT_DIR_OWNER}:${REPORT_DIR_OWNER}" "$REPORT_DIR" 2>/dev/null || true
fi
# ============================================================
# API KEYS
# ============================================================
VT_API_KEY="${VT_API_KEY:-}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
GREYNOISE_API_KEY="${GREYNOISE_API_KEY:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
IPINFO_TOKEN="${IPINFO_TOKEN:-}"
# ============================================================
# SESSION STATE
# ============================================================
WORST_EXIT=0
ANY_MALICIOUS=0
# Per-session summary (parallel arrays, one entry per scanned IP)
SESSION_IPS=()
SESSION_SEVERITIES=()
SESSION_SCORES=()
SESSION_MALICIOUS=()
# All temp dirs ever created, for interrupt-safe cleanup
ALL_TMP_DIRS=()
sev_to_code() {
    case "$1" in
        CRITICAL) echo 3 ;;
        HIGH)     echo 2 ;;
        MEDIUM)   echo 1 ;;
        *)        echo 0 ;;
    esac
}
# Coerce a value to a safe integer. Anything non-numeric (empty,
# "null", "Unknown", rate-limit error strings, etc.) becomes 0 so
# downstream arithmetic comparisons never crash and never silently
# misbehave on a malformed / unavailable API response.
sanitize_int() {
    local v="${1:-}"
    if [[ "$v" =~ ^-?[0-9]+$ ]]; then
        echo "$v"
    else
        echo 0
    fi
}
# Validates that a string looks like an actual DNS hostname (labels of
# letters/digits/hyphens, dot-separated). Used to reject dig error text
# (e.g. ";; communications error to ...#53: timed out") that a broken
# or unreachable resolver can print to stdout instead of a real PTR
# record — without this, such text would be silently treated as valid
# reverse-DNS data.
is_valid_hostname() {
    local h="${1:-}"
    [[ -z "$h" ]] && return 1
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}
# Validates that a DNSBL answer is an actual listing response, i.e. an
# address in the 127.0.0.0/8 loopback range that DNSBLs use as their
# "listed" signal — as opposed to resolver/network error text, which
# some dig/libresolv configurations print to stdout even with stderr
# redirected. Only a value that passes this check is ever treated as
# "this IP is listed"; anything else is reported as a failed lookup,
# never as a false "not listed" or false "listed".
is_valid_dnsbl_response() {
    local v="${1:-}"
    [[ "$v" =~ ^127\.0\.0\.[0-9]{1,3}$ ]]
}
# Renders a 20-block ASCII bar for a 0-100 score, e.g. [████████░░░░░░░░░░░░]
draw_risk_bar() {
    local score
    score="$(sanitize_int "${1:-0}")"
    [[ "$score" -gt 100 ]] && score=100
    [[ "$score" -lt 0 ]] && score=0
    local width=20
    local filled=$(( score * width / 100 ))
    local empty=$(( width - filled ))
    local bar="["
    local i
    for ((i = 0; i < filled; i++)); do bar+="█"; done
    for ((i = 0; i < empty; i++)); do bar+="░"; done
    bar+="]"
    echo "$bar"
}
# ============================================================
# HTML REPORT RENDERER SETUP
#
# Written once per session to a stable temp file (not the per-scan
# $TMP dir, which is deleted when each scan_ip() call returns) and
# reused for every IP scanned. Purely additive: nothing here is used
# by, or changes the result of, scoring / the TXT report / the exit
# code. If this file can't be written, HTML generation is silently
# skipped later and the rest of the tool behaves exactly as before.
# ============================================================
RENDER_HTML_SCRIPT=""
_setup_html_renderer() {
    local f
    f="$(mktemp)" || return 1
    cat > "$f" <<'PYEOF'
#!/usr/bin/env python3
import sys, json, html

def esc(x):
    if x is None:
        return ""
    return html.escape(str(x), quote=True)

CSS = r"""
:root {
  --bg: #0b0f14; --panel: #121821; --panel2: #161d28; --border: #232c3a;
  --text: #e6edf3; --muted: #8b98a9; --accent: #4da3ff;
  --ok: #5ee6a0; --ok-bg: rgba(94,230,160,0.08);
  --warn: #ffcc66; --warn-bg: rgba(255,204,102,0.08);
  --bad: #ff6b6b; --bad-bg: rgba(255,107,107,0.1);
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5; padding: 32px 16px 80px;
}
.wrap { max-width: 980px; margin: 0 auto; }
.header {
  display: flex; justify-content: space-between; align-items: flex-start;
  flex-wrap: wrap; gap: 16px; border-bottom: 1px solid var(--border);
  padding-bottom: 24px; margin-bottom: 24px;
}
.header h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: -0.3px; word-break: break-word; }
.header .sub { color: var(--muted); font-size: 14px; }
.header .meta { color: var(--muted); font-size: 13px; text-align: right; }
.score-panel {
  display: flex; align-items: center; gap: 20px; background: var(--panel);
  border: 1px solid var(--border); border-radius: 14px; padding: 20px 24px; margin-bottom: 24px;
  flex-wrap: wrap;
}
.score-ring {
  width: 96px; height: 96px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
  background: conic-gradient(var(--sev-fg) var(--score-pct), #232c3a var(--score-pct) 100%);
  flex-shrink: 0;
}
.score-ring-inner {
  width: 74px; height: 74px; border-radius: 50%; background: var(--panel);
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.score-ring-inner .num { font-size: 22px; font-weight: 700; }
.score-ring-inner .lbl { font-size: 10px; color: var(--muted); }
.sev-tag {
  display: inline-block; padding: 4px 12px; border-radius: 999px; font-weight: 700;
  font-size: 13px; letter-spacing: 0.5px; color: var(--sev-fg); background: var(--sev-bg);
  border: 1px solid var(--sev-fg);
}
.malicious-banner {
  background: var(--bad-bg); border: 1px solid var(--bad); color: var(--bad); font-weight: 700;
  text-align: center; padding: 14px; border-radius: 10px; margin-bottom: 24px; letter-spacing: 0.3px;
}
.section { margin-bottom: 28px; }
.section h2 {
  font-size: 15px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted);
  margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
}
.src-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; }
.src-card {
  display: flex; gap: 10px; align-items: flex-start; background: var(--panel);
  border: 1px solid var(--border); border-radius: 10px; padding: 12px;
}
.src-card.src-ok { border-left: 3px solid var(--ok); }
.src-card.src-warn { border-left: 3px solid var(--warn); }
.src-icon {
  width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0; display: flex;
  align-items: center; justify-content: center; font-size: 12px; font-weight: 700;
}
.src-ok .src-icon { background: var(--ok-bg); color: var(--ok); }
.src-warn .src-icon { background: var(--warn-bg); color: var(--warn); }
.src-name { font-size: 13px; font-weight: 600; }
.src-note { font-size: 12px; color: var(--muted); margin-top: 2px; }
ul.findings { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.finding { padding: 10px 14px; border-radius: 8px; font-size: 14px; }
.finding.bad { background: var(--bad-bg); border-left: 3px solid var(--bad); }
.finding.warn { background: var(--warn-bg); border-left: 3px solid var(--warn); }
.finding.ok { background: var(--ok-bg); border-left: 3px solid var(--ok); }
table.kv { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }
table.kv th, table.kv td { text-align: left; padding: 10px 14px; font-size: 13px; border-bottom: 1px solid var(--border); word-break: break-word; }
table.kv th { color: var(--muted); font-weight: 500; width: 34%; }
table.kv tr:last-child th, table.kv tr:last-child td { border-bottom: none; }
.muted { color: var(--muted); }
.intel-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.intel-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
.intel-card.bad { border-top: 3px solid var(--bad); }
.intel-card.warn { border-top: 3px solid var(--warn); }
.intel-card.ok { border-top: 3px solid var(--ok); }
.intel-title { font-weight: 700; font-size: 13px; margin-bottom: 6px; }
.intel-line { font-size: 12.5px; color: var(--muted); word-break: break-word; }
.src-link { display: inline-block; margin-top: 8px; font-size: 12px; color: var(--accent); text-decoration: none; }
.src-link:hover { text-decoration: underline; }
.links-grid { display: flex; flex-wrap: wrap; gap: 8px; }
.link-chip {
  font-size: 12.5px; color: var(--text); background: var(--panel2); border: 1px solid var(--border);
  border-radius: 999px; padding: 6px 14px; text-decoration: none;
}
.link-chip:hover { border-color: var(--accent); color: var(--accent); }
pre.raw {
  background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px;
  font-size: 12.5px; overflow-x: auto; color: var(--muted); white-space: pre-wrap; word-break: break-word;
}
footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }
"""

def intel_card(title, level_class, line1, line2=None, url=None):
    link_html = f'<a class="src-link" href="{esc(url)}" target="_blank" rel="noopener">Investigate &#8594;</a>' if url else ""
    line2_html = f'<div class="intel-line">{esc(line2)}</div>' if line2 else ""
    return (
        f'<div class="intel-card {level_class}">'
        f'<div class="intel-title">{esc(title)}</div>'
        f'<div class="intel-line">{esc(line1)}</div>'
        f'{line2_html}{link_html}</div>'
    )

def main():
    if len(sys.argv) < 3:
        print("usage: render_html.py <in.json> <out.html>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)

    sev = d.get("severity", "LOW")
    sev_colors = {
        "CRITICAL": ("#ff4d4d", "#3a0d0d"),
        "HIGH":     ("#ff6b6b", "#3a1414"),
        "MEDIUM":   ("#ffcc66", "#3a2f0d"),
        "LOW":      ("#5ee6a0", "#0d3a22"),
    }
    sev_fg, sev_bg = sev_colors.get(sev, sev_colors["LOW"])
    try:
        score = int(d.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))
    malicious = bool(d.get("malicious", False))
    ip = d.get("ip", "")

    src_html = []
    for s in d.get("sources", []):
        ok = bool(s.get("ok"))
        note = s.get("note") or ""
        cls = "src-ok" if ok else "src-warn"
        icon = "&#10003;" if ok else "!"
        note_html = f'<div class="src-note">{esc(note)}</div>' if note else ""
        src_html.append(
            f'<div class="src-card {cls}"><div class="src-icon">{icon}</div>'
            f'<div class="src-body"><div class="src-name">{esc(s.get("name"))}</div>{note_html}</div></div>'
        )

    finding_html = []
    findings = d.get("findings", []) or []
    if not findings:
        finding_html.append('<li class="finding ok">No significant malicious indicators detected by configured sources.</li>')
    else:
        for fi in findings:
            level = fi.get("level", "warn")
            finding_html.append(f'<li class="finding {esc(level)}">{esc(fi.get("text"))}</li>')
    for w in (d.get("config_warnings", []) or []):
        finding_html.append(f'<li class="finding warn">{esc(w.get("text"))}</li>')

    net = d.get("network", {})
    net_rows = [
        ("Organization", net.get("org")), ("ASN", net.get("asn")),
        ("Network Name", net.get("netname")), ("Hostname", net.get("hostname")),
        ("Reverse DNS", net.get("rdns")), ("Country", net.get("country")),
        ("Region", net.get("region")), ("City", net.get("city")),
        ("Usage Type", net.get("usage")), ("ISP", net.get("isp")),
        ("Domain", net.get("domain")),
    ]
    net_html = "".join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in net_rows)

    cymru = d.get("cymru", {})
    if cymru.get("ok"):
        cymru_rows = [
            ("ASN", "AS" + str(cymru.get("asn"))), ("AS Name", cymru.get("asname")),
            ("Country", cymru.get("country")), ("Registry", cymru.get("registry")),
            ("Allocated", cymru.get("allocated")),
        ]
        cymru_html = "".join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in cymru_rows)
    else:
        cymru_html = '<tr><td colspan="2" class="muted">Unavailable</td></tr>'

    intel = d.get("intel", {})
    vt = intel.get("vt", {}); abuse = intel.get("abuse", {}); gn = intel.get("gn", {})
    otx = intel.get("otx", {}); idb = intel.get("idb", {})
    spamhaus = intel.get("spamhaus", {}); spamcop = intel.get("spamcop", {}); barracuda = intel.get("barracuda", {})

    vt_level = "bad" if (vt.get("malicious") or 0) > 0 else ("warn" if (vt.get("suspicious") or 0) > 0 else "ok")
    a_score = abuse.get("score") or 0
    abuse_level = "bad" if a_score >= 70 else ("warn" if a_score >= 20 else "ok")
    gn_class = gn.get("classification", "unknown")
    gn_level = "bad" if gn_class == "malicious" else ("warn" if gn_class == "suspicious" else ("ok" if gn_class == "benign" else "warn"))
    otx_level = "warn" if (otx.get("pulses") or 0) > 0 else "ok"
    idb_level = "bad" if (idb.get("vulns") or 0) > 0 else "ok"
    spamhaus_level = "bad" if spamhaus.get("listed") else "ok"
    spamcop_level = "bad" if spamcop.get("listed") else "ok"
    barracuda_level = "bad" if barracuda.get("listed") else "ok"
    blocklist_count = intel.get("blocklist_count") or 0

    intel_cards = "".join([
        intel_card("VirusTotal", vt_level, vt.get("line"), url=f"https://www.virustotal.com/gui/ip-address/{ip}"),
        intel_card("AbuseIPDB", abuse_level, abuse.get("line"), url=f"https://www.abuseipdb.com/check/{ip}"),
        intel_card("GreyNoise", gn_level, gn.get("line1"), gn.get("line2"), url=f"https://viz.greynoise.io/ip/{ip}"),
        intel_card("AlienVault OTX", otx_level, otx.get("line"), url=f"https://otx.alienvault.com/indicator/ip/{ip}"),
        intel_card("Shodan InternetDB", idb_level, idb.get("line"), url=f"https://internetdb.shodan.io/{ip}"),
        intel_card("Spamhaus ZEN", spamhaus_level, spamhaus.get("line"), url=f"https://check.spamhaus.org/results/?searchterm={ip}"),
        intel_card("SpamCop", spamcop_level, "LISTED" if spamcop.get("listed") else "Not listed", url=f"https://www.spamcop.net/w3m?action=checkblock&ip={ip}"),
        intel_card("Barracuda", barracuda_level, "LISTED" if barracuda.get("listed") else "Not listed", url=f"https://www.barracudacentral.org/lookups?ip={ip}"),
    ])
    if blocklist_count >= 2:
        bl_note = f"{blocklist_count} of 3 blocklists (Spamhaus/SpamCop/Barracuda) flag this IP — strong consensus."
    elif blocklist_count == 1:
        bl_note = "1 of 3 blocklists flags this IP."
    else:
        bl_note = "0 of 3 blocklists flag this IP."
    intel_cards += intel_card("Blocklist Consensus", "bad" if blocklist_count >= 2 else ("warn" if blocklist_count == 1 else "ok"), bl_note)

    links_html = "".join(
        f'<a class="link-chip" href="{esc(l.get("url"))}" target="_blank" rel="noopener">{esc(l.get("label"))}</a>'
        for l in (d.get("links", []) or [])
    )

    idb_detail_rows = [
        ("Open Ports", idb.get("ports")), ("Known CVEs", idb.get("vuln_list")),
        ("Tags", idb.get("tags")), ("Hostnames", idb.get("hostnames")), ("CPEs (services)", idb.get("cpes")),
    ]
    idb_detail_html = "".join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in idb_detail_rows)

    malicious_banner = ""
    if malicious:
        malicious_banner = f'<div class="malicious-banner">&#9888; CONFIRMED MALICIOUS INDICATOR(S) DETECTED FOR {esc(ip)}</div>'

    whois_raw = (d.get("whois_raw") or "").strip()
    rdap_raw = (d.get("rdap_raw") or "").strip()

    inline_vars = f':root {{ --sev-fg: {sev_fg}; --sev-bg: {sev_bg}; --score-pct: {score}%; }}'

    html_out = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IP Intelligence Report - {esc(ip)}</title>
<style>
{CSS}
{inline_vars}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div>
      <h1>{esc(ip)}</h1>
      <div class="sub">IP Security Intelligence Report</div>
    </div>
    <div class="meta">
      Generated {esc(d.get("timestamp"))} UTC<br>
      Version {esc(d.get("version"))}
    </div>
  </div>

  {malicious_banner}

  <div class="score-panel">
    <div class="score-ring"><div class="score-ring-inner">
      <div class="num">{score}</div>
      <div class="lbl">/ 100</div>
    </div></div>
    <div>
      <div class="sev-tag">{esc(sev)}</div>
      <div class="muted" style="margin-top:8px; font-size:13px;">Composite risk score across all configured sources</div>
    </div>
  </div>

  <div class="section">
    <h2>Sources Checked</h2>
    <div class="src-grid">{"".join(src_html)}</div>
  </div>

  <div class="section">
    <h2>Major Findings</h2>
    <ul class="findings">{"".join(finding_html)}</ul>
  </div>

  <div class="section">
    <h2>Network / Ownership</h2>
    <table class="kv">{net_html}</table>
  </div>

  <div class="section">
    <h2>Team Cymru ASN Cross-Check</h2>
    <table class="kv">{cymru_html}</table>
  </div>

  <div class="section">
    <h2>Security Intelligence Results</h2>
    <div class="intel-grid">{intel_cards}</div>
  </div>

  <div class="section">
    <h2>Shodan InternetDB Details</h2>
    <table class="kv">{idb_detail_html}</table>
  </div>

  <div class="section">
    <h2>Investigation Links</h2>
    <div class="links-grid">{links_html}</div>
  </div>

  <div class="section">
    <h2>RDAP Registration</h2>
    <pre class="raw">{esc(rdap_raw) if rdap_raw else "(unavailable)"}</pre>
  </div>

  <div class="section">
    <h2>WHOIS Registration</h2>
    <pre class="raw">{esc(whois_raw) if whois_raw else "(unavailable)"}</pre>
  </div>

  <footer>IP Security Intelligence &middot; Version {esc(d.get("version"))} &middot; local investigative use</footer>
</div>
</body>
</html>'''

    with open(sys.argv[2], "w", encoding="utf-8") as out:
        out.write(html_out)

if __name__ == "__main__":
    main()
PYEOF
    RENDER_HTML_SCRIPT="$f"
}
_setup_html_renderer || warn "Could not prepare HTML report renderer — HTML reports will be skipped this session (TXT reports are unaffected)."
# Global cleanup — fires on normal exit AND on Ctrl-C/SIGTERM, so a
# scan interrupted mid-flight never leaks its temp directory (or the
# session-level HTML renderer script).
cleanup_all_tmp() {
    local d
    for d in "${ALL_TMP_DIRS[@]:-}"; do
        [[ -n "$d" && -d "$d" ]] && rm -rf "$d" 2>/dev/null
    done
    [[ -n "$RENDER_HTML_SCRIPT" && -f "$RENDER_HTML_SCRIPT" ]] && rm -f "$RENDER_HTML_SCRIPT" 2>/dev/null
}
trap cleanup_all_tmp EXIT
trap 'cleanup_all_tmp; echo; bad "Interrupted."; exit 130' INT
trap 'cleanup_all_tmp; exit 143' TERM
# ============================================================
# BANNER
# ============================================================
clear 2>/dev/null || true
echo
echo -e "${BOLD}${CYAN}============================================================${NC}"
echo -e "${BOLD}${CYAN}              IP SECURITY INTELLIGENCE${NC}"
echo -e "${BOLD}${CYAN}                    Version $VERSION${NC}"
echo -e "${BOLD}${CYAN}============================================================${NC}"
echo
echo "Reports saved under: $REPORT_DIR"
echo "  Text reports : $TEXT_REPORT_DIR"
echo "  HTML reports : $HTML_REPORT_DIR"
echo
[[ -z "$VT_API_KEY" ]] &&
    warn "VT_API_KEY not set — VirusTotal will be marked NOT CONFIGURED"
[[ -z "$ABUSEIPDB_API_KEY" ]] &&
    warn "ABUSEIPDB_API_KEY not set — AbuseIPDB will be marked NOT CONFIGURED"
[[ -z "$GREYNOISE_API_KEY" ]] &&
    warn "GREYNOISE_API_KEY not set — the Community endpoint also requires a free key (sign up at https://viz.greynoise.io/); without one GreyNoise lookups will fail, not just run 'unauthenticated'"
[[ -z "$OTX_API_KEY" ]] &&
    warn "OTX_API_KEY not set — OTX public lookup will be attempted"
echo
echo "Enter an IP to scan."
echo "Type 'history' to browse past scans, 'quit'/'exit', or leave blank + Enter to stop."
echo
# ============================================================
# IP VALIDATION
# ============================================================
is_valid_ip() {
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
}
# ============================================================
# SAFE JSON VALUE
# ============================================================
json_value() {
    local file="$1"
    local query="$2"
    local default="${3:-Unknown}"
    if [[ -s "$file" ]] && jq empty "$file" >/dev/null 2>&1; then
        jq -r "$query // \"$default\"" "$file" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}
# ============================================================
# SCAN SINGLE IP
# ============================================================
scan_ip() {
    local IP="$1"
    local TIMESTAMP
    local SAFE_IP
    local REPORT
    local TMP
    TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
    SAFE_IP="$(echo "$IP" | tr ':' '_')"
    REPORT="${TEXT_REPORT_DIR}/IP_${SAFE_IP}_${TIMESTAMP}.txt"
    TMP="$(mktemp -d)"
    ALL_TMP_DIRS+=("$TMP")
    trap 'rm -rf "$TMP"' RETURN
    echo
    echo -e "${BOLD}${CYAN}============================================================${NC}"
    echo -e "${BOLD}${CYAN}             SCANNING: $IP${NC}"
    echo -e "${BOLD}${CYAN}============================================================${NC}"
    echo
    # ========================================================
    # INITIAL FILES
    # ========================================================
    : > "$TMP/rdns.txt"
    : > "$TMP/whois.txt"
    echo '{}' > "$TMP/rdap.json"
    echo '{}' > "$TMP/ipinfo.json"
    echo '{}' > "$TMP/virustotal.json"
    echo '{}' > "$TMP/abuseipdb.json"
    echo '{}' > "$TMP/greynoise.json"
    echo '{}' > "$TMP/otx.json"
    echo '{}' > "$TMP/internetdb.json"
    : > "$TMP/cymru.txt"
    : > "$TMP/spamcop.txt"
    : > "$TMP/barracuda.txt"
    # ========================================================
    # PARALLEL LOOKUPS
    # ========================================================
    info "Running 13 lookups in parallel (RDAP, WHOIS, IPinfo, Cymru, VT, AbuseIPDB, GreyNoise, OTX, InternetDB, 3x DNSBL)..."
    echo
    # --------------------------------------------------------
    # RDAP
    # --------------------------------------------------------
    (
        curl -sS \
            --connect-timeout 10 \
            --max-time 30 \
            -L \
            "https://rdap.arin.net/registry/ip/$IP" \
            -o "$TMP/rdap.json" \
            2>/dev/null
    ) &
    PID_RDAP=$!
    # --------------------------------------------------------
    # REVERSE DNS
    # --------------------------------------------------------
    (
        dig +short +time=5 +tries=1 -x "$IP" > "$TMP/rdns.txt" 2>/dev/null
    ) &
    PID_RDNS=$!
    # --------------------------------------------------------
    # WHOIS
    # --------------------------------------------------------
    (
        timeout 30 whois "$IP" > "$TMP/whois.txt" 2>/dev/null
    ) &
    PID_WHOIS=$!
    # --------------------------------------------------------
    # IPINFO
    # --------------------------------------------------------
    (
        if [[ -n "$IPINFO_TOKEN" ]]; then
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                "https://ipinfo.io/$IP/json?token=$IPINFO_TOKEN" \
                -o "$TMP/ipinfo.json" \
                2>/dev/null
        else
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                "https://ipinfo.io/$IP/json" \
                -o "$TMP/ipinfo.json" \
                2>/dev/null
        fi
    ) &
    PID_IPINFO=$!
    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------
    if [[ -n "$VT_API_KEY" ]]; then
        (
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
                -H "x-apikey: $VT_API_KEY" \
                -H "Accept: application/json" \
                -o "$TMP/virustotal.json" \
                2>/dev/null
        ) &
    else
        (
            echo '{"__not_configured__":true}' > "$TMP/virustotal.json"
        ) &
    fi
    PID_VT=$!
    # --------------------------------------------------------
    # ABUSEIPDB
    # --------------------------------------------------------
    if [[ -n "$ABUSEIPDB_API_KEY" ]]; then
        (
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -G \
                "https://api.abuseipdb.com/api/v2/check" \
                --data-urlencode "ipAddress=$IP" \
                --data-urlencode "maxAgeInDays=90" \
                -H "Key: $ABUSEIPDB_API_KEY" \
                -H "Accept: application/json" \
                -o "$TMP/abuseipdb.json" \
                2>/dev/null
        ) &
    else
        (
            echo '{"__not_configured__":true}' > "$TMP/abuseipdb.json"
        ) &
    fi
    PID_ABUSE=$!
    # ========================================================
    # GREYNOISE
    #
    # Community endpoint:  https://api.greynoise.io/v3/community/$IP
    # Authenticated:       https://api.greynoise.io/v3/ip/$IP
    # ========================================================
    if [[ -n "$GREYNOISE_API_KEY" ]]; then
        (
            HTTP_CODE="$(curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                -w '%{http_code}' \
                "https://api.greynoise.io/v3/ip/$IP" \
                -H "key: $GREYNOISE_API_KEY" \
                -H "Accept: application/json" \
                -o "$TMP/greynoise.json" \
                2>/dev/null)"
            echo "${HTTP_CODE:-000}" > "$TMP/greynoise_http.txt"
        ) &
    else
        (
            HTTP_CODE="$(curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                -w '%{http_code}' \
                "https://api.greynoise.io/v3/community/$IP" \
                -H "Accept: application/json" \
                -o "$TMP/greynoise.json" \
                2>/dev/null)"
            echo "${HTTP_CODE:-000}" > "$TMP/greynoise_http.txt"
        ) &
    fi
    PID_GN=$!
    # --------------------------------------------------------
    # ALIENVAULT OTX
    # --------------------------------------------------------
    (
        if [[ -n "$OTX_API_KEY" ]]; then
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" \
                -H "X-OTX-API-KEY: $OTX_API_KEY" \
                -H "Accept: application/json" \
                -o "$TMP/otx.json" \
                2>/dev/null
        else
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" \
                -H "Accept: application/json" \
                -o "$TMP/otx.json" \
                2>/dev/null
        fi
    ) &
    PID_OTX=$!
    # --------------------------------------------------------
    # SHODAN INTERNETDB (free, no API key required)
    #
    # Passive weekly snapshot of open ports / CVEs / tags Shodan has
    # already observed for this IP. This does NOT actively probe the
    # target itself — it queries Shodan's existing scan data, same as
    # the other reputation sources.
    # IPv4 only.
    # --------------------------------------------------------
    (
        if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            curl -sS \
                --connect-timeout 10 \
                --max-time 30 \
                -L \
                "https://internetdb.shodan.io/$IP" \
                -H "Accept: application/json" \
                -o "$TMP/internetdb.json" \
                2>/dev/null
        else
            echo '{"__not_applicable__":true}' > "$TMP/internetdb.json"
        fi
    ) &
    PID_IDB=$!
    # --------------------------------------------------------
    # SPAMHAUS ZEN DNSBL (free, no API key, passive DNS lookup)
    #
    # Queries Spamhaus's public blocklist via a reverse-octet DNS
    # lookup — the same mechanism mail servers use. A response in
    # 127.0.0.x means the IP is currently listed; the exact value
    # indicates which Spamhaus list matched. IPv4 only.
    # --------------------------------------------------------
    (
        if [[ "$IP" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            REVERSED="${BASH_REMATCH[4]}.${BASH_REMATCH[3]}.${BASH_REMATCH[2]}.${BASH_REMATCH[1]}"
            dig +short +time=5 +tries=1 "${REVERSED}.zen.spamhaus.org" > "$TMP/spamhaus.txt" 2>/dev/null
        else
            : > "$TMP/spamhaus.txt"
        fi
    ) &
    PID_SPAMHAUS=$!
    # --------------------------------------------------------
    # TEAM CYMRU IP-TO-ASN (free, no API key, single whois round trip)
    #
    # Authoritative BGP-origin ASN lookup, independent of ARIN RDAP/
    # WHOIS and of IPinfo's org string. Used as a cross-check and
    # fallback for ASN/country/registry data.
    # --------------------------------------------------------
    (
        timeout 15 whois -h whois.cymru.com " -v $IP" > "$TMP/cymru.txt" 2>/dev/null
    ) &
    PID_CYMRU=$!
    # --------------------------------------------------------
    # SPAMCOP DNSBL (free, no API key, passive DNS lookup)
    # --------------------------------------------------------
    (
        if [[ "$IP" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            REVERSED="${BASH_REMATCH[4]}.${BASH_REMATCH[3]}.${BASH_REMATCH[2]}.${BASH_REMATCH[1]}"
            dig +short +time=5 +tries=1 "${REVERSED}.bl.spamcop.net" > "$TMP/spamcop.txt" 2>/dev/null
        else
            : > "$TMP/spamcop.txt"
        fi
    ) &
    PID_SPAMCOP=$!
    # --------------------------------------------------------
    # BARRACUDA REPUTATION DNSBL (free, no API key, passive DNS lookup)
    # --------------------------------------------------------
    (
        if [[ "$IP" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            REVERSED="${BASH_REMATCH[4]}.${BASH_REMATCH[3]}.${BASH_REMATCH[2]}.${BASH_REMATCH[1]}"
            dig +short +time=5 +tries=1 "${REVERSED}.b.barracudacentral.org" > "$TMP/barracuda.txt" 2>/dev/null
        else
            : > "$TMP/barracuda.txt"
        fi
    ) &
    PID_BARRACUDA=$!
    # ========================================================
    # WAIT (with live spinner)
    # ========================================================
    local ALL_PIDS=(
        "$PID_RDAP" "$PID_RDNS" "$PID_WHOIS" "$PID_IPINFO"
        "$PID_VT" "$PID_ABUSE" "$PID_GN" "$PID_OTX" "$PID_IDB"
        "$PID_SPAMHAUS" "$PID_CYMRU" "$PID_SPAMCOP" "$PID_BARRACUDA"
    )
    local TOTAL_JOBS=${#ALL_PIDS[@]}
    local SPIN_CHARS='|/-\'
    local SPIN_I=0
    local ALIVE PID_CHECK DONE_COUNT CH
    while true; do
        ALIVE=0
        for PID_CHECK in "${ALL_PIDS[@]}"; do
            kill -0 "$PID_CHECK" 2>/dev/null && ALIVE=$((ALIVE + 1))
        done
        DONE_COUNT=$((TOTAL_JOBS - ALIVE))
        CH="${SPIN_CHARS:$((SPIN_I % ${#SPIN_CHARS})):1}"
        printf '\r  %b%s%b Querying %d sources... %d/%d complete   ' \
            "${CYAN}" "$CH" "${NC}" "$TOTAL_JOBS" "$DONE_COUNT" "$TOTAL_JOBS"
        [[ "$ALIVE" -eq 0 ]] && break
        SPIN_I=$((SPIN_I + 1))
        sleep 0.15
    done
    printf '\r%-70s\r' " "
    wait "${ALL_PIDS[@]}" 2>/dev/null || true
    # ========================================================
    # RDAP
    # ========================================================
    local RDAP_OK="true"
    if jq empty "$TMP/rdap.json" >/dev/null 2>&1 &&
       jq -e '.objectClassName' "$TMP/rdap.json" >/dev/null 2>&1; then
        ok "RDAP query completed"
    else
        echo '{}' > "$TMP/rdap.json"
        RDAP_OK="false"
        warn "RDAP query unavailable"
    fi
    # ========================================================
    # REVERSE DNS
    # ========================================================
    local RDNS
    local RDNS_OK="true"
    local RDNS_RAW
    RDNS_RAW="$(head -n 1 "$TMP/rdns.txt" 2>/dev/null | sed 's/\.$//' || true)"
    # A resolver/network failure (e.g. "no servers could be reached",
    # "communications error to X#53: timed out") can print its error
    # text to stdout depending on the local dig/resolver setup, even
    # with stderr redirected. That text is NOT a PTR record and must
    # never be treated as one — validate it looks like an actual
    # hostname before trusting it, so a broken resolver can't be
    # silently mistaken for "no PTR record" (which is normal) or,
    # worse, leak garbage into the report as if it were real data.
    if [[ -n "$RDNS_RAW" ]] && is_valid_hostname "$RDNS_RAW"; then
        RDNS="$RDNS_RAW"
        ok "Reverse DNS: $RDNS"
    elif [[ -n "$RDNS_RAW" ]]; then
        RDNS="None"
        RDNS_OK="false"
        warn "Reverse DNS lookup failed (resolver/network error, not a valid PTR record) — treat as UNKNOWN, not 'no record'"
    else
        warn "No reverse DNS record"
        RDNS="None"
        RDNS_OK="false"
    fi
    # ========================================================
    # WHOIS
    # ========================================================
    local WHOIS_OK="true"
    [[ -s "$TMP/whois.txt" ]] || { : > "$TMP/whois.txt"; WHOIS_OK="false"; }
    local WHOIS_ASN
    local WHOIS_NETNAME
    WHOIS_ASN="$(
        grep -iE '^[[:space:]]*(origin(as)?|origin):' \
            "$TMP/whois.txt" |
        head -n 1 |
        cut -d: -f2- |
        xargs 2>/dev/null || true
    )"
    WHOIS_NETNAME="$(
        grep -iE '^[[:space:]]*(netname|NetName):' \
            "$TMP/whois.txt" |
        head -n 1 |
        cut -d: -f2- |
        xargs 2>/dev/null || true
    )"
    [[ -n "$WHOIS_ASN" ]] || WHOIS_ASN="Not available"
    [[ -n "$WHOIS_NETNAME" ]] || WHOIS_NETNAME="Not available"
    # ========================================================
    # IPINFO
    # ========================================================
    local IPINFO_ORG
    local IPINFO_COUNTRY
    local IPINFO_REGION
    local IPINFO_CITY
    local IPINFO_HOSTNAME
    local IPINFO_OK="true"
    if jq empty "$TMP/ipinfo.json" >/dev/null 2>&1 &&
       jq -e 'type == "object"' "$TMP/ipinfo.json" >/dev/null 2>&1; then
        IPINFO_ORG="$(jq -r '.org // "Unknown"' "$TMP/ipinfo.json")"
        IPINFO_COUNTRY="$(jq -r '.country // "Unknown"' "$TMP/ipinfo.json")"
        IPINFO_REGION="$(jq -r '.region // "Unknown"' "$TMP/ipinfo.json")"
        IPINFO_CITY="$(jq -r '.city // "Unknown"' "$TMP/ipinfo.json")"
        IPINFO_HOSTNAME="$(jq -r '.hostname // "None"' "$TMP/ipinfo.json")"
        ok "Organization: $IPINFO_ORG"
        ok "Location: $IPINFO_CITY, $IPINFO_REGION, $IPINFO_COUNTRY"
        if [[ "$IPINFO_HOSTNAME" != "None" ]]; then
            ok "Hostname: $IPINFO_HOSTNAME"
        fi
    else
        IPINFO_ORG="Unknown"
        IPINFO_COUNTRY="Unknown"
        IPINFO_REGION="Unknown"
        IPINFO_CITY="Unknown"
        IPINFO_HOSTNAME="None"
        IPINFO_OK="false"
        warn "IPinfo unavailable"
    fi
    # ========================================================
    # TEAM CYMRU IP-TO-ASN
    # ========================================================
    local CYMRU_CONFIGURED="true"
    local CYMRU_ASN="Unknown"
    local CYMRU_CC="Unknown"
    local CYMRU_REGISTRY="Unknown"
    local CYMRU_ALLOCATED="Unknown"
    local CYMRU_ASNAME="Unknown"
    if [[ -s "$TMP/cymru.txt" ]]; then
        local CYMRU_LINE
        CYMRU_LINE="$(grep -v '^AS ' "$TMP/cymru.txt" | grep '|' | head -n 1 || true)"
        if [[ -n "$CYMRU_LINE" ]]; then
            CYMRU_ASN="$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}')"
            CYMRU_CC="$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$4); print $4}')"
            CYMRU_REGISTRY="$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$5); print $5}')"
            CYMRU_ALLOCATED="$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$6); print $6}')"
            CYMRU_ASNAME="$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$7); print $7}')"
            [[ -n "$CYMRU_ASN" && "$CYMRU_ASN" != "NA" ]] || CYMRU_ASN="Unknown"
            [[ -n "$CYMRU_CC" ]] || CYMRU_CC="Unknown"
            [[ -n "$CYMRU_REGISTRY" ]] || CYMRU_REGISTRY="Unknown"
            [[ -n "$CYMRU_ALLOCATED" ]] || CYMRU_ALLOCATED="Unknown"
            [[ -n "$CYMRU_ASNAME" ]] || CYMRU_ASNAME="Unknown"
            if [[ "$CYMRU_ASN" != "Unknown" ]]; then
                ok "Team Cymru: AS$CYMRU_ASN ($CYMRU_ASNAME)"
            else
                warn "Team Cymru: no ASN data for this IP"
            fi
        else
            CYMRU_CONFIGURED="false"
            warn "Team Cymru: unavailable (no parseable response)"
        fi
    else
        CYMRU_CONFIGURED="false"
        warn "Team Cymru: unavailable (request failed)"
    fi
    # ========================================================
    # ASN FALLBACK
    #
    # Priority: 1) ARIN WHOIS OriginAS, 2) Team Cymru (authoritative,
    # independent source), 3) AS-number parsed from IPinfo's org string.
    # ========================================================
    if [[ "$WHOIS_ASN" == "Not available" &&
          "$CYMRU_ASN" != "Unknown" ]]; then
        WHOIS_ASN="AS${CYMRU_ASN}"
    fi
    if [[ "$WHOIS_ASN" == "Not available" &&
          "$IPINFO_ORG" =~ ^(AS[0-9]+) ]]; then
        WHOIS_ASN="${BASH_REMATCH[1]}"
    fi
    # ========================================================
    # ABUSEIPDB VARIABLES
    # ========================================================
    local ABUSE_CONFIGURED="true"
    local ABUSE_SCORE=0
    local ABUSE_REPORTS=0
    local ABUSE_USAGE="Unknown"
    local ABUSE_ISP="Unknown"
    local ABUSE_DOMAIN="Unknown"
    if jq -e '.__not_configured__ == true' \
        "$TMP/abuseipdb.json" >/dev/null 2>&1; then
        ABUSE_CONFIGURED="false"
        warn "AbuseIPDB: not configured"
    elif jq empty "$TMP/abuseipdb.json" >/dev/null 2>&1 &&
         jq -e '.data' "$TMP/abuseipdb.json" >/dev/null 2>&1; then
        ABUSE_SCORE="$(sanitize_int "$(jq -r '.data.abuseConfidenceScore // 0' "$TMP/abuseipdb.json")")"
        ABUSE_REPORTS="$(sanitize_int "$(jq -r '.data.totalReports // 0' "$TMP/abuseipdb.json")")"
        ABUSE_USAGE="$(jq -r '.data.usageType // "Unknown"' "$TMP/abuseipdb.json")"
        ABUSE_ISP="$(jq -r '.data.isp // "Unknown"' "$TMP/abuseipdb.json")"
        ABUSE_DOMAIN="$(jq -r '.data.domain // "Unknown"' "$TMP/abuseipdb.json")"
        if [[ "$ABUSE_SCORE" -ge 70 ]]; then
            bad "AbuseIPDB: ${ABUSE_SCORE}% confidence / $ABUSE_REPORTS reports"
        elif [[ "$ABUSE_SCORE" -ge 20 ]]; then
            warn "AbuseIPDB: ${ABUSE_SCORE}% confidence / $ABUSE_REPORTS reports"
        else
            ok "AbuseIPDB: ${ABUSE_SCORE}% confidence / $ABUSE_REPORTS reports"
        fi
    else
        ABUSE_CONFIGURED="false"
        warn "AbuseIPDB unavailable"
    fi
    # ========================================================
    # VIRUSTOTAL
    # ========================================================
    local VT_CONFIGURED="true"
    local VT_MALICIOUS=0
    local VT_SUSPICIOUS=0
    local VT_HARMLESS=0
    local VT_UNDETECTED=0
    local VT_REPUTATION=0
    local VT_LAST_ANALYSIS="Unknown"
    if jq -e '.__not_configured__ == true' \
        "$TMP/virustotal.json" >/dev/null 2>&1; then
        VT_CONFIGURED="false"
        warn "VirusTotal: not configured"
    elif jq empty "$TMP/virustotal.json" >/dev/null 2>&1 &&
         jq -e '.data.attributes.last_analysis_stats' \
            "$TMP/virustotal.json" >/dev/null 2>&1; then
        VT_MALICIOUS="$(sanitize_int "$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$TMP/virustotal.json")")"
        VT_SUSPICIOUS="$(sanitize_int "$(jq -r '.data.attributes.last_analysis_stats.suspicious // 0' "$TMP/virustotal.json")")"
        VT_HARMLESS="$(sanitize_int "$(jq -r '.data.attributes.last_analysis_stats.harmless // 0' "$TMP/virustotal.json")")"
        VT_UNDETECTED="$(sanitize_int "$(jq -r '.data.attributes.last_analysis_stats.undetected // 0' "$TMP/virustotal.json")")"
        VT_REPUTATION="$(sanitize_int "$(jq -r '.data.attributes.reputation // 0' "$TMP/virustotal.json")")"
        VT_LAST_ANALYSIS="$(
            jq -r '
                (.data.attributes.last_analysis_date // empty)
                | if . == "" then "Unknown"
                  else tonumber | todate
                  end
            ' "$TMP/virustotal.json" 2>/dev/null ||
            echo "Unknown"
        )"
        if [[ "$VT_MALICIOUS" -gt 0 ]]; then
            bad "VirusTotal: $VT_MALICIOUS malicious detection(s)"
        elif [[ "$VT_SUSPICIOUS" -gt 0 ]]; then
            warn "VirusTotal: $VT_SUSPICIOUS suspicious detection(s)"
        else
            ok "VirusTotal: 0 malicious detections"
        fi
    else
        VT_CONFIGURED="false"
        warn "VirusTotal unavailable"
    fi
    # ========================================================
    # GREYNOISE PARSING
    # ========================================================
    local GN_CONFIGURED="false"
    local GN_CLASSIFICATION="unknown"
    local GN_NOISE="false"
    local GN_RIOT="false"
    local GN_NAME="Unknown"
    local GN_ACTOR="Unknown"
    local GN_TAGS="None"
    local GN_LAST_SEEN="Unknown"
    local GN_HTTP
    local GN_QUERY_OK="false"
    if [[ -n "$GREYNOISE_API_KEY" ]]; then
        GN_CONFIGURED="true"
    fi
    GN_HTTP="$(cat "$TMP/greynoise_http.txt" 2>/dev/null || echo "000")"
    [[ "$GN_HTTP" =~ ^[0-9]+$ ]] || GN_HTTP="000"
    if [[ "$GN_HTTP" == "200" ]]; then
        GN_QUERY_OK="true"
    elif [[ "$GN_HTTP" == "404" ]]; then
        # GreyNoise returns 404 for an IP it has never seen — that IS a
        # valid, meaningful answer ("not observed"), not a failure.
        GN_QUERY_OK="true"
        GN_CLASSIFICATION="not_observed"
    fi
    if [[ "$GN_QUERY_OK" != "true" ]]; then
        GN_CLASSIFICATION="query_failed"
        if [[ "$GN_HTTP" == "401" || "$GN_HTTP" == "403" ]]; then
            warn "GreyNoise: authentication failed (HTTP $GN_HTTP)$( [[ -z "$GREYNOISE_API_KEY" ]] && echo ' — no API key was sent; the Community endpoint requires one, see https://viz.greynoise.io/' )"
        elif [[ "$GN_HTTP" == "000" ]]; then
            warn "GreyNoise: request failed (no response / network error)"
        else
            warn "GreyNoise: request failed (HTTP $GN_HTTP)"
        fi
    elif [[ "$GN_CLASSIFICATION" == "not_observed" ]]; then
        ok "GreyNoise: IP not observed in GreyNoise's dataset"
    elif jq empty "$TMP/greynoise.json" >/dev/null 2>&1 &&
       [[ "$(jq -r 'type' "$TMP/greynoise.json" 2>/dev/null)" == "object" ]]; then
        GN_CLASSIFICATION="$(
            jq -r '(.internet_scanner_intelligence.classification // .classification // "unknown")' \
                "$TMP/greynoise.json" 2>/dev/null | tr '[:upper:]' '[:lower:]'
        )"
        GN_NOISE="$(
            jq -r '(.noise // .internet_scanner_intelligence.noise // false)' \
                "$TMP/greynoise.json" 2>/dev/null | tr '[:upper:]' '[:lower:]'
        )"
        GN_RIOT="$(
            jq -r '(.riot // .internet_scanner_intelligence.riot // false)' \
                "$TMP/greynoise.json" 2>/dev/null | tr '[:upper:]' '[:lower:]'
        )"
        GN_NAME="$(
            jq -r '(.name // .internet_scanner_intelligence.name // "Unknown")' \
                "$TMP/greynoise.json" 2>/dev/null
        )"
        GN_ACTOR="$(
            jq -r '(.internet_scanner_intelligence.actor // .actor // "Unknown")' \
                "$TMP/greynoise.json" 2>/dev/null
        )"
        GN_TAGS="$(
            jq -r '
                (.internet_scanner_intelligence.tags // .tags // [])
                | if type == "array"
                  then map(if type == "object" then (.name // .tag // tostring) else tostring end) | join(", ")
                  else tostring
                  end
            ' "$TMP/greynoise.json" 2>/dev/null
        )"
        GN_LAST_SEEN="$(
            jq -r '(.internet_scanner_intelligence.last_seen // .last_seen // "Unknown")' \
                "$TMP/greynoise.json" 2>/dev/null
        )"
        [[ -n "$GN_CLASSIFICATION" ]] || GN_CLASSIFICATION="unknown"
        [[ -n "$GN_ACTOR" ]] || GN_ACTOR="Unknown"
        [[ -n "$GN_TAGS" ]] || GN_TAGS="None"
        [[ -n "$GN_LAST_SEEN" ]] || GN_LAST_SEEN="Unknown"
        case "$GN_CLASSIFICATION" in
            malicious)  bad "GreyNoise: MALICIOUS" ;;
            suspicious) warn "GreyNoise: SUSPICIOUS" ;;
            benign)     ok "GreyNoise: BENIGN" ;;
            *)          warn "GreyNoise: $GN_CLASSIFICATION" ;;
        esac
        if [[ "$GN_NOISE" == "true" ]]; then
            finding "GreyNoise observed this IP generating Internet scanning/noise."
        fi
        if [[ "$GN_RIOT" == "true" ]]; then
            finding "GreyNoise identifies this IP as RIOT/known benign infrastructure."
        fi
        if [[ "$GN_ACTOR" != "Unknown" ]]; then
            finding "GreyNoise actor: $GN_ACTOR"
        fi
    else
        warn "GreyNoise unavailable"
    fi
    # ========================================================
    # ALIENVAULT OTX
    # ========================================================
    local OTX_CONFIGURED="true"
    local OTX_PULSES=0
    if jq empty "$TMP/otx.json" >/dev/null 2>&1 &&
       jq -e '.pulse_info' "$TMP/otx.json" >/dev/null 2>&1; then
        OTX_PULSES="$(sanitize_int "$(jq -r '.pulse_info.count // 0' "$TMP/otx.json")")"
        if [[ "$OTX_PULSES" -gt 0 ]]; then
            warn "AlienVault OTX: $OTX_PULSES pulse(s)"
        else
            ok "AlienVault OTX: 0 pulses"
        fi
    else
        OTX_CONFIGURED="false"
        warn "AlienVault OTX unavailable"
    fi
    # ========================================================
    # SHODAN INTERNETDB
    # ========================================================
    local IDB_CONFIGURED="true"
    local IDB_PORTS="None"
    local IDB_VULNS="None"
    local IDB_TAGS="None"
    local IDB_HOSTNAMES="None"
    local IDB_CPES="None"
    local IDB_VULN_COUNT=0
    if jq -e '.__not_applicable__ == true' "$TMP/internetdb.json" >/dev/null 2>&1; then
        IDB_CONFIGURED="false"
        warn "Shodan InternetDB: not applicable (IPv6)"
    elif jq empty "$TMP/internetdb.json" >/dev/null 2>&1 &&
         jq -e '.ports' "$TMP/internetdb.json" >/dev/null 2>&1; then
        IDB_PORTS="$(jq -r '(.ports // []) | map(tostring) | join(", ")' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_VULNS="$(jq -r '(.vulns // []) | join(", ")' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_TAGS="$(jq -r '(.tags // []) | join(", ")' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_HOSTNAMES="$(jq -r '(.hostnames // []) | join(", ")' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_CPES="$(jq -r '(.cpes // []) | join(", ")' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_VULN_COUNT="$(jq -r '(.vulns // []) | length' "$TMP/internetdb.json" 2>/dev/null)"
        IDB_VULN_COUNT="$(sanitize_int "$IDB_VULN_COUNT")"
        [[ -n "$IDB_PORTS" ]] || IDB_PORTS="None"
        [[ -n "$IDB_VULNS" ]] || IDB_VULNS="None"
        [[ -n "$IDB_TAGS" ]] || IDB_TAGS="None"
        [[ -n "$IDB_HOSTNAMES" ]] || IDB_HOSTNAMES="None"
        [[ -n "$IDB_CPES" ]] || IDB_CPES="None"
        if [[ "$IDB_VULN_COUNT" -gt 0 ]]; then
            bad "Shodan InternetDB: $IDB_VULN_COUNT known CVE(s), ports: $IDB_PORTS"
        elif [[ "$IDB_PORTS" != "None" ]]; then
            ok "Shodan InternetDB: ports: $IDB_PORTS"
        else
            ok "Shodan InternetDB: no data"
        fi
    else
        # 404 from InternetDB means Shodan has no scan data for this IP —
        # a normal, common outcome, not an error.
        IDB_CONFIGURED="false"
        ok "Shodan InternetDB: no data on file for this IP"
    fi
    # ========================================================
    # SPAMHAUS ZEN DNSBL
    # ========================================================
    local SPAMHAUS_CONFIGURED="true"
    local SPAMHAUS_LISTED="false"
    local SPAMHAUS_REASON="Not listed"
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SPAMHAUS_CONFIGURED="false"
        warn "Spamhaus ZEN: not applicable (IPv6)"
    else
        local SH_RESULT
        SH_RESULT="$(head -n 1 "$TMP/spamhaus.txt" 2>/dev/null || true)"
        if [[ -z "$SH_RESULT" ]]; then
            ok "Spamhaus ZEN: not listed"
        elif is_valid_dnsbl_response "$SH_RESULT"; then
            SPAMHAUS_LISTED="true"
            case "$SH_RESULT" in
                *127.0.0.2)  SPAMHAUS_REASON="Listed: SBL (spam source)" ;;
                *127.0.0.3)  SPAMHAUS_REASON="Listed: SBL (spammer domain/exploit)" ;;
                *127.0.0.4|*127.0.0.5|*127.0.0.6|*127.0.0.7)
                    SPAMHAUS_REASON="Listed: XBL (compromised/exploited host, e.g. bot/malware infection)" ;;
                *127.0.0.9)  SPAMHAUS_REASON="Listed: SBL DROP/EDROP (hijacked/malicious netblock)" ;;
                *127.0.0.10|*127.0.0.11)
                    SPAMHAUS_REASON="Listed: PBL (dynamic/residential IP not meant to send mail directly)" ;;
                *) SPAMHAUS_REASON="Listed: $SH_RESULT" ;;
            esac
            bad "Spamhaus ZEN: $SPAMHAUS_REASON"
        else
            # Non-empty but not a real 127.0.0.x DNSBL answer — almost
            # always resolver/network error text leaking onto stdout.
            # This must NEVER be scored as a listing.
            SPAMHAUS_CONFIGURED="false"
            SPAMHAUS_REASON="Lookup failed (unexpected response, not a listing)"
            warn "Spamhaus ZEN: lookup failed — unexpected response was not a valid DNSBL answer (likely a local resolver/network error): ${SH_RESULT:0:80}"
        fi
    fi
    # ========================================================
    # SPAMCOP DNSBL
    # ========================================================
    local SPAMCOP_CONFIGURED="true"
    local SPAMCOP_LISTED="false"
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SPAMCOP_CONFIGURED="false"
        warn "SpamCop: not applicable (IPv6)"
    else
        local SC_RESULT
        SC_RESULT="$(head -n 1 "$TMP/spamcop.txt" 2>/dev/null || true)"
        if [[ -z "$SC_RESULT" ]]; then
            ok "SpamCop: not listed"
        elif is_valid_dnsbl_response "$SC_RESULT"; then
            SPAMCOP_LISTED="true"
            bad "SpamCop: LISTED (known spam source)"
        else
            SPAMCOP_CONFIGURED="false"
            warn "SpamCop: lookup failed — unexpected response was not a valid DNSBL answer (likely a local resolver/network error): ${SC_RESULT:0:80}"
        fi
    fi
    # ========================================================
    # BARRACUDA REPUTATION DNSBL
    # ========================================================
    local BARRACUDA_CONFIGURED="true"
    local BARRACUDA_LISTED="false"
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        BARRACUDA_CONFIGURED="false"
        warn "Barracuda: not applicable (IPv6)"
    else
        local BC_RESULT
        BC_RESULT="$(head -n 1 "$TMP/barracuda.txt" 2>/dev/null || true)"
        if [[ -z "$BC_RESULT" ]]; then
            ok "Barracuda: not listed"
        elif is_valid_dnsbl_response "$BC_RESULT"; then
            BARRACUDA_LISTED="true"
            bad "Barracuda: LISTED (poor reputation)"
        else
            BARRACUDA_CONFIGURED="false"
            warn "Barracuda: lookup failed — unexpected response was not a valid DNSBL answer (likely a local resolver/network error): ${BC_RESULT:0:80}"
        fi
    fi
    # ========================================================
    # BLOCKLIST CONSENSUS
    # ========================================================
    local BLOCKLIST_COUNT=0
    [[ "$SPAMHAUS_LISTED" == "true" ]] && BLOCKLIST_COUNT=$((BLOCKLIST_COUNT + 1))
    [[ "$SPAMCOP_LISTED" == "true" ]] && BLOCKLIST_COUNT=$((BLOCKLIST_COUNT + 1))
    [[ "$BARRACUDA_LISTED" == "true" ]] && BLOCKLIST_COUNT=$((BLOCKLIST_COUNT + 1))
    # ========================================================
    # RISK SCORE (weighted / composite)
    # ========================================================
    local SCORE=0
    local FINDINGS=()
    if [[ "$VT_MALICIOUS" -ge 10 ]]; then
        SCORE=$((SCORE + 45)); FINDINGS+=("VirusTotal reports $VT_MALICIOUS malicious detections.")
    elif [[ "$VT_MALICIOUS" -ge 5 ]]; then
        SCORE=$((SCORE + 35)); FINDINGS+=("VirusTotal reports $VT_MALICIOUS malicious detections.")
    elif [[ "$VT_MALICIOUS" -ge 2 ]]; then
        SCORE=$((SCORE + 25)); FINDINGS+=("VirusTotal reports $VT_MALICIOUS malicious detections.")
    elif [[ "$VT_MALICIOUS" -eq 1 ]]; then
        SCORE=$((SCORE + 10)); FINDINGS+=("VirusTotal reports 1 malicious detection.")
    fi
    if [[ "$VT_SUSPICIOUS" -ge 5 ]]; then
        SCORE=$((SCORE + 10)); FINDINGS+=("VirusTotal reports $VT_SUSPICIOUS suspicious detections.")
    elif [[ "$VT_SUSPICIOUS" -gt 0 ]]; then
        SCORE=$((SCORE + 5)); FINDINGS+=("VirusTotal reports $VT_SUSPICIOUS suspicious detection(s).")
    fi
    if [[ "$ABUSE_SCORE" -ge 90 ]]; then
        SCORE=$((SCORE + 40)); FINDINGS+=("AbuseIPDB confidence is ${ABUSE_SCORE}%.")
    elif [[ "$ABUSE_SCORE" -ge 70 ]]; then
        SCORE=$((SCORE + 30)); FINDINGS+=("AbuseIPDB confidence is ${ABUSE_SCORE}%.")
    elif [[ "$ABUSE_SCORE" -ge 40 ]]; then
        SCORE=$((SCORE + 20)); FINDINGS+=("AbuseIPDB confidence is ${ABUSE_SCORE}%.")
    elif [[ "$ABUSE_SCORE" -ge 10 ]]; then
        SCORE=$((SCORE + 10)); FINDINGS+=("AbuseIPDB confidence is ${ABUSE_SCORE}%.")
    fi
    if [[ "$ABUSE_REPORTS" -ge 100 ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("AbuseIPDB has $ABUSE_REPORTS reports.")
    elif [[ "$ABUSE_REPORTS" -ge 20 ]]; then
        SCORE=$((SCORE + 10)); FINDINGS+=("AbuseIPDB has $ABUSE_REPORTS reports.")
    elif [[ "$ABUSE_REPORTS" -ge 5 ]]; then
        SCORE=$((SCORE + 5)); FINDINGS+=("AbuseIPDB has $ABUSE_REPORTS reports.")
    fi
    case "$GN_CLASSIFICATION" in
        malicious)
            SCORE=$((SCORE + 35)); FINDINGS+=("GreyNoise classifies the IP as malicious.")
            ;;
        suspicious)
            SCORE=$((SCORE + 20)); FINDINGS+=("GreyNoise classifies the IP as suspicious.")
            ;;
    esac
    if [[ "$GN_NOISE" == "true" ]]; then
        SCORE=$((SCORE + 10)); FINDINGS+=("GreyNoise observed Internet scanning/noise from this IP.")
    fi
    if [[ "$OTX_PULSES" -ge 20 ]]; then
        SCORE=$((SCORE + 25)); FINDINGS+=("AlienVault OTX has $OTX_PULSES related pulses.")
    elif [[ "$OTX_PULSES" -ge 5 ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("AlienVault OTX has $OTX_PULSES related pulses.")
    elif [[ "$OTX_PULSES" -ge 1 ]]; then
        SCORE=$((SCORE + 5)); FINDINGS+=("AlienVault OTX has $OTX_PULSES related pulse(s).")
    fi
    if [[ "$IDB_VULN_COUNT" -ge 5 ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("Shodan InternetDB lists $IDB_VULN_COUNT known CVEs on this host.")
    elif [[ "$IDB_VULN_COUNT" -ge 1 ]]; then
        SCORE=$((SCORE + 8)); FINDINGS+=("Shodan InternetDB lists $IDB_VULN_COUNT known CVE(s) on this host.")
    fi
    if [[ "$SPAMHAUS_LISTED" == "true" ]]; then
        SCORE=$((SCORE + 25)); FINDINGS+=("Spamhaus ZEN: $SPAMHAUS_REASON")
    fi
    if [[ "$SPAMCOP_LISTED" == "true" ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("SpamCop lists this IP as a known spam source.")
    fi
    if [[ "$BARRACUDA_LISTED" == "true" ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("Barracuda Reputation lists this IP with poor reputation.")
    fi
    if [[ "$BLOCKLIST_COUNT" -ge 2 ]]; then
        SCORE=$((SCORE + 15)); FINDINGS+=("$BLOCKLIST_COUNT of 3 blocklists (Spamhaus/SpamCop/Barracuda) flag this IP — strong consensus.")
    fi
    [[ "$SCORE" -gt 100 ]] && SCORE=100
    local SEVERITY
    if [[ "$SCORE" -ge 80 ]]; then
        SEVERITY="CRITICAL"
    elif [[ "$SCORE" -ge 60 ]]; then
        SEVERITY="HIGH"
    elif [[ "$SCORE" -ge 30 ]]; then
        SEVERITY="MEDIUM"
    else
        SEVERITY="LOW"
    fi
    # ========================================================
    # CONFIRMED-MALICIOUS OVERRIDE
    #
    # A weighted composite score can bury a single hard signal
    # (e.g. one VT malicious hit only adds 10 points). This check
    # is independent of the weighted score: if ANY source gives a
    # direct malicious confirmation, the IP is treated as malicious
    # in the final outcome no matter what the composite score says.
    # ========================================================
    local IP_MALICIOUS="false"
    if [[ "$VT_MALICIOUS" -gt 0 ]] ||
       [[ "$ABUSE_SCORE" -ge 75 ]] ||
       [[ "$GN_CLASSIFICATION" == "malicious" ]] ||
       [[ "$SPAMHAUS_LISTED" == "true" ]] ||
       [[ "$SPAMCOP_LISTED" == "true" ]] ||
       [[ "$BARRACUDA_LISTED" == "true" ]]; then
        IP_MALICIOUS="true"
        ANY_MALICIOUS=1
        case "$SEVERITY" in
            LOW|MEDIUM)
                SEVERITY="HIGH"
                FINDINGS+=("Severity escalated to HIGH: at least one source directly confirmed malicious activity, overriding the weighted score.")
                ;;
        esac
    fi
    local THIS_CODE
    THIS_CODE="$(sev_to_code "$SEVERITY")"
    [[ "$THIS_CODE" -gt "$WORST_EXIT" ]] && WORST_EXIT="$THIS_CODE"
    SESSION_IPS+=("$IP")
    SESSION_SEVERITIES+=("$SEVERITY")
    SESSION_SCORES+=("$SCORE")
    SESSION_MALICIOUS+=("$IP_MALICIOUS")
    # ========================================================
    # MAJOR FINDINGS
    # ========================================================
    section "MAJOR FINDINGS"
    finding "IP address       : $IP"
    finding "Organization     : $IPINFO_ORG"
    finding "ASN information  : $WHOIS_ASN"
    finding "Reverse DNS      : $RDNS"
    finding "Location         : $IPINFO_CITY, $IPINFO_REGION, $IPINFO_COUNTRY"
    finding "Usage type       : $ABUSE_USAGE"
    echo
    if [[ "${#FINDINGS[@]}" -eq 0 ]]; then
        ok "No significant malicious indicators detected by configured sources."
    else
        for item in "${FINDINGS[@]}"; do
            case "$item" in
                *malicious*|*MALICIOUS*|*detections*|*detection.*|*escalated*|*Spamhaus*)
                    bad "$item"
                    ;;
                *)
                    warn "$item"
                    ;;
            esac
        done
    fi
    [[ "$VT_CONFIGURED" == "false" ]] &&
        warn "VirusTotal was not checked — treat as UNKNOWN, not clean."
    [[ "$ABUSE_CONFIGURED" == "false" ]] &&
        warn "AbuseIPDB was not checked — treat as UNKNOWN, not clean."
    [[ "$OTX_CONFIGURED" == "false" ]] &&
        warn "AlienVault OTX was not checked — treat as UNKNOWN, not clean."
    [[ "$GN_QUERY_OK" != "true" ]] &&
        warn "GreyNoise was not successfully queried (HTTP $GN_HTTP) — treat as UNKNOWN, not clean."
    # ========================================================
    # RISK ASSESSMENT
    # ========================================================
    section "RISK ASSESSMENT"
    local RISK_BAR
    RISK_BAR="$(draw_risk_bar "$SCORE")"
    case "$SEVERITY" in
        CRITICAL|HIGH)
            echo -e "${RED}${BOLD}[-] Risk Score : $RISK_BAR $SCORE / 100${NC}"
            echo -e "${RED}${BOLD}[-] Severity   : $SEVERITY${NC}"
            ;;
        MEDIUM)
            echo -e "${YELLOW}${BOLD}[!] Risk Score : $RISK_BAR $SCORE / 100${NC}"
            echo -e "${YELLOW}${BOLD}[!] Severity   : $SEVERITY${NC}"
            ;;
        *)
            echo -e "${GREEN}[+] Risk Score : $RISK_BAR $SCORE / 100${NC}"
            echo -e "${GREEN}[+] Severity   : $SEVERITY${NC}"
            ;;
    esac
    if [[ "$IP_MALICIOUS" == "true" ]]; then
        echo
        echo -e "${RED}${BOLD}############################################################${NC}"
        echo -e "${RED}${BOLD}#   CONFIRMED MALICIOUS INDICATOR(S) DETECTED FOR: $IP${NC}"
        echo -e "${RED}${BOLD}############################################################${NC}"
    fi
    # ========================================================
    # SOURCES CHECKED (console) — same at-a-glance grid the report
    # gets, but shown live instead of only after the file is written.
    # ========================================================
    section "SOURCES CHECKED"
    console_src_row() {
        local name="$1" ok_flag="$2" note="${3:-}"
        if [[ "$ok_flag" == "true" ]]; then
            printf '  %b✓%b %-20s %bOK%b\n' "${GREEN}${BOLD}" "${NC}" "$name" "${GREEN}" "${NC}"
        else
            printf '  %b!%b %-20s %b%s%b\n' "${YELLOW}${BOLD}" "${NC}" "$name" "${YELLOW}" "${note:-UNAVAILABLE}" "${NC}"
        fi
    }
    console_src_row "RDAP" "$RDAP_OK"
    console_src_row "Reverse DNS" "$RDNS_OK" "$( [[ "$RDNS_OK" == "false" ]] && echo 'no PTR / resolver issue' )"
    console_src_row "WHOIS" "$WHOIS_OK"
    console_src_row "IPinfo" "$IPINFO_OK"
    console_src_row "Team Cymru ASN" "$CYMRU_CONFIGURED"
    console_src_row "VirusTotal" "$VT_CONFIGURED" "$( [[ -z "$VT_API_KEY" ]] && echo 'no API key' )"
    console_src_row "AbuseIPDB" "$ABUSE_CONFIGURED" "$( [[ -z "$ABUSEIPDB_API_KEY" ]] && echo 'no API key' )"
    if [[ "$GN_QUERY_OK" == "true" ]]; then
        console_src_row "GreyNoise" "true"
    else
        console_src_row "GreyNoise" "false" "HTTP $GN_HTTP"
    fi
    console_src_row "AlienVault OTX" "$OTX_CONFIGURED"
    console_src_row "Shodan InternetDB" "$IDB_CONFIGURED" "IPv6 / no scan data"
    console_src_row "Spamhaus ZEN" "$SPAMHAUS_CONFIGURED"
    console_src_row "SpamCop" "$SPAMCOP_CONFIGURED"
    console_src_row "Barracuda" "$BARRACUDA_CONFIGURED"
    unset -f console_src_row
    # ========================================================
    # AT-A-GLANCE SUMMARY LINE
    # ========================================================
    local SUMMARY_COLOR SUMMARY_TAG
    case "$SEVERITY" in
        CRITICAL|HIGH) SUMMARY_COLOR="${RED}${BOLD}" ;;
        MEDIUM)        SUMMARY_COLOR="${YELLOW}${BOLD}" ;;
        *)             SUMMARY_COLOR="${GREEN}" ;;
    esac
    if [[ "$IP_MALICIOUS" == "true" ]]; then
        SUMMARY_TAG="MALICIOUS CONFIRMED"
    else
        SUMMARY_TAG="no confirmed malicious indicator"
    fi
    echo
    printf '  %b▸ %-15s  %-8s  score %3s/100  %s%b\n' "$SUMMARY_COLOR" "$IP" "$SEVERITY" "$SCORE" "$SUMMARY_TAG" "${NC}"
    # ========================================================
    # REPORT VALUES
    # ========================================================
    local VT_REPORT_LINE
    local ABUSE_REPORT_LINE
    local GN_REPORT_LINE
    local GN_SECOND_LINE
    local OTX_REPORT_LINE
    local IDB_REPORT_LINE
    local SPAMHAUS_REPORT_LINE
    if [[ "$VT_CONFIGURED" == "true" ]]; then
        VT_REPORT_LINE="Malicious: $VT_MALICIOUS | Suspicious: $VT_SUSPICIOUS | Harmless: $VT_HARMLESS | Undetected: $VT_UNDETECTED | Reputation: $VT_REPUTATION | Last analysis: $VT_LAST_ANALYSIS"
    else
        VT_REPORT_LINE="NOT CHECKED (API key missing or request failed)"
    fi
    if [[ "$ABUSE_CONFIGURED" == "true" ]]; then
        ABUSE_REPORT_LINE="Confidence: ${ABUSE_SCORE}% | Reports: $ABUSE_REPORTS | Usage: $ABUSE_USAGE | ISP: $ABUSE_ISP | Domain: $ABUSE_DOMAIN"
    else
        ABUSE_REPORT_LINE="NOT CHECKED (API key missing or request failed)"
    fi
    GN_REPORT_LINE="Classification: $GN_CLASSIFICATION | Noise: $GN_NOISE | RIOT: $GN_RIOT | Name: $GN_NAME"
    GN_SECOND_LINE="Actor: $GN_ACTOR | Tags: $GN_TAGS | Last Seen: $GN_LAST_SEEN"
    if [[ "$OTX_CONFIGURED" == "true" ]]; then
        OTX_REPORT_LINE="Pulses: $OTX_PULSES"
    else
        OTX_REPORT_LINE="NOT CHECKED (request failed or unavailable)"
    fi
    if [[ "$IDB_CONFIGURED" == "true" ]]; then
        IDB_REPORT_LINE="Ports: $IDB_PORTS | Vulns: $IDB_VULNS | Tags: $IDB_TAGS"
    else
        IDB_REPORT_LINE="No data (either IPv6, or Shodan has not scanned this host)"
    fi
    if [[ "$SPAMHAUS_CONFIGURED" == "true" ]]; then
        SPAMHAUS_REPORT_LINE="$SPAMHAUS_REASON"
    else
        SPAMHAUS_REPORT_LINE="Not checked (IPv6 not supported by this lookup)"
    fi
    # ========================================================
    # WRITE REPORT
    # ========================================================
    info "Writing text report..."
    {
        echo "============================================================"
        echo "              IP SECURITY INTELLIGENCE REPORT"
        echo "                    Version $VERSION"
        echo "============================================================"
        echo "IP              : $IP"
        echo "Generated UTC   : $TIMESTAMP"
        echo
        echo "------------------------------------------------------------"
        echo "RISK ASSESSMENT"
        echo "------------------------------------------------------------"
        case "$SEVERITY" in
            CRITICAL|HIGH)
                printf '%b\n' "${RED}${BOLD}Risk Score      : $RISK_BAR $SCORE / 100${NC}"
                printf '%b\n' "${RED}${BOLD}Severity        : $SEVERITY${NC}"
                ;;
            MEDIUM)
                printf '%b\n' "${YELLOW}${BOLD}Risk Score      : $RISK_BAR $SCORE / 100${NC}"
                printf '%b\n' "${YELLOW}${BOLD}Severity        : $SEVERITY${NC}"
                ;;
            *)
                printf '%b\n' "${GREEN}Risk Score      : $RISK_BAR $SCORE / 100${NC}"
                printf '%b\n' "${GREEN}Severity        : $SEVERITY${NC}"
                ;;
        esac
        if [[ "$IP_MALICIOUS" == "true" ]]; then
            echo
            printf '%b\n' "${RED}${BOLD}############################################################${NC}"
            printf '%b\n' "${RED}${BOLD}#   CONFIRMED MALICIOUS INDICATOR(S) DETECTED FOR: $IP${NC}"
            printf '%b\n' "${RED}${BOLD}############################################################${NC}"
        fi
        echo
        echo "------------------------------------------------------------"
        echo "SOURCES CHECKED"
        echo "------------------------------------------------------------"
        src_row() {
            local name="$1" ok_flag="$2" note="${3:-}"
            if [[ "$ok_flag" == "true" ]]; then
                printf '  %b%-14s%b %-22s\n' "${GREEN}" "[OK]" "${NC}" "$name"
            else
                printf '  %b%-14s%b %-22s %s\n' "${YELLOW}" "[UNAVAILABLE]" "${NC}" "$name" "$note"
            fi
        }
        src_row "RDAP" "$RDAP_OK"
        src_row "Reverse DNS" "$RDNS_OK" "(no PTR record — often normal)"
        src_row "WHOIS" "$WHOIS_OK"
        src_row "IPinfo" "$IPINFO_OK"
        src_row "Team Cymru ASN" "$CYMRU_CONFIGURED"
        src_row "VirusTotal" "$VT_CONFIGURED" "$( [[ -z "$VT_API_KEY" ]] && echo '(no API key)' )"
        src_row "AbuseIPDB" "$ABUSE_CONFIGURED" "$( [[ -z "$ABUSEIPDB_API_KEY" ]] && echo '(no API key)' )"
        if [[ "$GN_QUERY_OK" == "true" ]]; then
            src_row "GreyNoise" "true"
        else
            src_row "GreyNoise" "false" "(HTTP $GN_HTTP)"
        fi
        src_row "AlienVault OTX" "$OTX_CONFIGURED"
        src_row "Shodan InternetDB" "$IDB_CONFIGURED" "(IPv6 or no scan data)"
        src_row "Spamhaus ZEN" "$SPAMHAUS_CONFIGURED"
        src_row "SpamCop" "$SPAMCOP_CONFIGURED"
        src_row "Barracuda" "$BARRACUDA_CONFIGURED"
        unset -f src_row
        echo
        echo "------------------------------------------------------------"
        echo "MAJOR FINDINGS"
        echo "------------------------------------------------------------"
        if [[ "${#FINDINGS[@]}" -eq 0 ]]; then
            printf '%b\n' "${GREEN}- No significant malicious indicators detected by configured sources.${NC}"
        else
            for item in "${FINDINGS[@]}"; do
                case "$item" in
                    *malicious*|*MALICIOUS*|*detections*|*detection.*|*escalated*|*Spamhaus*)
                        printf '%b\n' "${RED}- $item${NC}"
                        ;;
                    *)
                        printf '%b\n' "${YELLOW}- $item${NC}"
                        ;;
                esac
            done
        fi
        [[ "$VT_CONFIGURED" == "false" ]] &&
            printf '%b\n' "${YELLOW}- VirusTotal was not checked — treat as UNKNOWN, not clean.${NC}"
        [[ "$ABUSE_CONFIGURED" == "false" ]] &&
            printf '%b\n' "${YELLOW}- AbuseIPDB was not checked — treat as UNKNOWN, not clean.${NC}"
        [[ "$OTX_CONFIGURED" == "false" ]] &&
            printf '%b\n' "${YELLOW}- AlienVault OTX was not checked — treat as UNKNOWN, not clean.${NC}"
        [[ "$GN_QUERY_OK" != "true" ]] &&
            printf '%b\n' "${YELLOW}- GreyNoise was not successfully queried (HTTP $GN_HTTP) — treat as UNKNOWN, not clean.${NC}"
        echo
        echo "------------------------------------------------------------"
        echo "NETWORK / OWNERSHIP"
        echo "------------------------------------------------------------"
        echo "Organization    : $IPINFO_ORG"
        echo "ASN             : $WHOIS_ASN"
        echo "Network Name    : $WHOIS_NETNAME"
        echo "Hostname        : $IPINFO_HOSTNAME"
        echo "Reverse DNS     : $RDNS"
        echo "Country         : $IPINFO_COUNTRY"
        echo "Region          : $IPINFO_REGION"
        echo "City            : $IPINFO_CITY"
        echo "Usage Type      : $ABUSE_USAGE"
        echo "ISP             : $ABUSE_ISP"
        echo "Domain          : $ABUSE_DOMAIN"
        echo
        if [[ "$CYMRU_CONFIGURED" == "true" && "$CYMRU_ASN" != "Unknown" ]]; then
            echo "Team Cymru cross-check (independent source):"
            echo "  ASN           : AS$CYMRU_ASN"
            echo "  AS Name       : $CYMRU_ASNAME"
            echo "  Country       : $CYMRU_CC"
            echo "  Registry      : $CYMRU_REGISTRY"
            echo "  Allocated     : $CYMRU_ALLOCATED"
        fi
        echo
        echo "------------------------------------------------------------"
        echo "REGISTRATION (RDAP)"
        echo "------------------------------------------------------------"
        if jq empty "$TMP/rdap.json" >/dev/null 2>&1 &&
           jq -e '.objectClassName' "$TMP/rdap.json" >/dev/null 2>&1; then
            jq -r '
                def values_for_role($role; $field):
                    [
                        .. |
                        objects |
                        select((.roles? // []) | index($role)) |
                        .vcardArray[1][]? |
                        select(.[0] == $field) |
                        .[3]
                    ] | flatten | map(select(. != null and . != "")) | unique;
                def first_value($arr; $default):
                    if ($arr | length) > 0 then $arr[0] else $default end;
                (first_value(values_for_role("registrant"; "org") + values_for_role("registrant"; "fn"); "Unknown")) as $registrant |
                (first_value(values_for_role("abuse"; "email"); "Not listed")) as $abuse |
                ((.cidr0_cidrs // []) | map("\(.v4prefix // .v6prefix // "?")/\(.length // "?")") | join(", ")) as $cidr |
                "Network Name : \(.name // "Unknown")",
                "IP Range     : \(.startAddress // "?") - \(.endAddress // "?")",
                "CIDR         : \($cidr)",
                "Reg. Type    : \(.type // "Unknown")",
                "Registrant   : \($registrant)",
                "Abuse Email  : \($abuse)"
            ' "$TMP/rdap.json" 2>/dev/null ||
                echo "(could not parse RDAP data)"
        else
            echo "(unavailable)"
        fi
        echo
        echo "------------------------------------------------------------"
        echo "REGISTRATION (WHOIS)"
        echo "------------------------------------------------------------"
        if [[ -s "$TMP/whois.txt" ]]; then
            grep -iE \
                '^[[:space:]]*(inetnum|NetRange|CIDR|route|origin|originAS|netname|NetName|OrgName|org-name|country|Country|created|last-modified|RegDate|Updated|OrgAbuseEmail|abuse-c|mnt-by|status):' \
                "$TMP/whois.txt" |
                awk '!seen[$0]++' |
                head -n 100 ||
                echo "(no key fields found)"
        else
            echo "(unavailable)"
        fi
        echo
        echo "============================================================"
        echo "             SECURITY INTELLIGENCE RESULTS"
        echo "============================================================"
        if [[ "$VT_MALICIOUS" -gt 0 ]]; then
            printf '%b\n' "${RED}VirusTotal      : $VT_REPORT_LINE${NC}"
        elif [[ "$VT_SUSPICIOUS" -gt 0 ]]; then
            printf '%b\n' "${YELLOW}VirusTotal      : $VT_REPORT_LINE${NC}"
        else
            printf '%b\n' "${GREEN}VirusTotal      : $VT_REPORT_LINE${NC}"
        fi
        if [[ "$ABUSE_SCORE" -ge 70 ]]; then
            printf '%b\n' "${RED}AbuseIPDB       : $ABUSE_REPORT_LINE${NC}"
        elif [[ "$ABUSE_SCORE" -ge 20 ]]; then
            printf '%b\n' "${YELLOW}AbuseIPDB       : $ABUSE_REPORT_LINE${NC}"
        else
            printf '%b\n' "${GREEN}AbuseIPDB       : $ABUSE_REPORT_LINE${NC}"
        fi
        case "$GN_CLASSIFICATION" in
            malicious)
                printf '%b\n' "${RED}GreyNoise       : $GN_REPORT_LINE${NC}"
                printf '%b\n' "${RED}                  $GN_SECOND_LINE${NC}"
                ;;
            suspicious)
                printf '%b\n' "${YELLOW}GreyNoise       : $GN_REPORT_LINE${NC}"
                printf '%b\n' "${YELLOW}                  $GN_SECOND_LINE${NC}"
                ;;
            benign)
                printf '%b\n' "${GREEN}GreyNoise       : $GN_REPORT_LINE${NC}"
                printf '%b\n' "${GREEN}                  $GN_SECOND_LINE${NC}"
                ;;
            *)
                printf '%b\n' "${YELLOW}GreyNoise       : $GN_REPORT_LINE${NC}"
                printf '%b\n' "${YELLOW}                  $GN_SECOND_LINE${NC}"
                ;;
        esac
        if [[ "$OTX_PULSES" -gt 0 ]]; then
            printf '%b\n' "${YELLOW}AlienVault OTX  : $OTX_REPORT_LINE${NC}"
        else
            printf '%b\n' "${GREEN}AlienVault OTX  : $OTX_REPORT_LINE${NC}"
        fi
        if [[ "$IDB_VULN_COUNT" -gt 0 ]]; then
            printf '%b\n' "${RED}Shodan InternetDB: $IDB_REPORT_LINE${NC}"
        else
            printf '%b\n' "${GREEN}Shodan InternetDB: $IDB_REPORT_LINE${NC}"
        fi
        if [[ "$SPAMHAUS_LISTED" == "true" ]]; then
            printf '%b\n' "${RED}Spamhaus ZEN    : $SPAMHAUS_REPORT_LINE${NC}"
        else
            printf '%b\n' "${GREEN}Spamhaus ZEN    : $SPAMHAUS_REPORT_LINE${NC}"
        fi
        if [[ "$SPAMCOP_LISTED" == "true" ]]; then
            printf '%b\n' "${RED}SpamCop         : LISTED${NC}"
        else
            printf '%b\n' "${GREEN}SpamCop         : Not listed${NC}"
        fi
        if [[ "$BARRACUDA_LISTED" == "true" ]]; then
            printf '%b\n' "${RED}Barracuda       : LISTED${NC}"
        else
            printf '%b\n' "${GREEN}Barracuda       : Not listed${NC}"
        fi
        if [[ "$BLOCKLIST_COUNT" -ge 2 ]]; then
            printf '%b\n' "${RED}${BOLD}Blocklist Consensus: $BLOCKLIST_COUNT of 3 lists flag this IP${NC}"
        elif [[ "$BLOCKLIST_COUNT" -eq 1 ]]; then
            printf '%b\n' "${YELLOW}Blocklist Consensus: $BLOCKLIST_COUNT of 3 lists flag this IP${NC}"
        else
            printf '%b\n' "${GREEN}Blocklist Consensus: 0 of 3 lists flag this IP${NC}"
        fi
        echo
        echo "============================================================"
        echo "                 INVESTIGATION LINKS"
        echo "============================================================"
        echo "VirusTotal      : https://www.virustotal.com/gui/ip-address/$IP"
        echo "AbuseIPDB       : https://www.abuseipdb.com/check/$IP"
        echo "GreyNoise       : https://viz.greynoise.io/ip/$IP"
        echo "Shodan          : https://www.shodan.io/host/$IP"
        echo "Shodan InternetDB: https://internetdb.shodan.io/$IP"
        echo "Censys          : https://search.censys.io/hosts/$IP"
        echo "AlienVault OTX  : https://otx.alienvault.com/indicator/ip/$IP"
        echo "URLScan         : https://urlscan.io/search/#ip:$IP"
        echo "Cisco Talos     : https://talosintelligence.com/reputation_center/lookup?search=$IP"
        echo "ThreatFox       : https://threatfox.abuse.ch/browse.php?search=$IP"
        echo "Feodo Tracker   : https://feodotracker.abuse.ch/browse.php?search=$IP"
        echo "IPinfo          : https://ipinfo.io/$IP"
        echo "BGP HE          : https://bgp.he.net/ip/$IP"
        echo "ARIN RDAP       : https://search.arin.net/rdap/?query=$IP"
        echo "Spamhaus IP Rep : https://check.spamhaus.org/results/?searchterm=$IP"
        echo "SpamCop         : https://www.spamcop.net/w3m?action=checkblock&ip=$IP"
        echo "Barracuda       : https://www.barracudacentral.org/lookups?ip=$IP"
        echo "Team Cymru ASN  : https://asn.cymru.com/cgi-bin/whois.cgi?asn=$CYMRU_ASN"
        echo
        echo "------------------------------------------------------------"
        echo "GREYNOISE DETAILS"
        echo "------------------------------------------------------------"
        case "$GN_CLASSIFICATION" in
            malicious)  printf '%b\n' "${RED}Classification  : $GN_CLASSIFICATION${NC}" ;;
            suspicious) printf '%b\n' "${YELLOW}Classification  : $GN_CLASSIFICATION${NC}" ;;
            benign)     printf '%b\n' "${GREEN}Classification  : $GN_CLASSIFICATION${NC}" ;;
            *)          echo "Classification  : $GN_CLASSIFICATION" ;;
        esac
        echo "Noise           : $GN_NOISE"
        echo "RIOT            : $GN_RIOT"
        echo "Name            : $GN_NAME"
        echo "Actor           : $GN_ACTOR"
        echo "Tags            : $GN_TAGS"
        echo "Last Seen       : $GN_LAST_SEEN"
        echo
        echo "------------------------------------------------------------"
        echo "SHODAN INTERNETDB DETAILS"
        echo "------------------------------------------------------------"
        echo "Open Ports      : $IDB_PORTS"
        echo "Known CVEs      : $IDB_VULNS"
        echo "Tags            : $IDB_TAGS"
        echo "Hostnames       : $IDB_HOSTNAMES"
        echo "CPEs (services) : $IDB_CPES"
        echo
        echo "------------------------------------------------------------"
        echo "BLOCKLIST DETAILS (Spamhaus / SpamCop / Barracuda)"
        echo "------------------------------------------------------------"
        echo "Spamhaus ZEN    : $SPAMHAUS_REPORT_LINE"
        echo "SpamCop         : $( [[ "$SPAMCOP_LISTED" == "true" ]] && echo "LISTED" || echo "Not listed" )"
        echo "Barracuda       : $( [[ "$BARRACUDA_LISTED" == "true" ]] && echo "LISTED" || echo "Not listed" )"
        echo "Consensus       : $BLOCKLIST_COUNT of 3 lists flag this IP"
        echo
        echo "------------------------------------------------------------"
        echo "TEAM CYMRU ASN DETAILS"
        echo "------------------------------------------------------------"
        if [[ "$CYMRU_CONFIGURED" == "true" && "$CYMRU_ASN" != "Unknown" ]]; then
            echo "ASN             : AS$CYMRU_ASN"
            echo "AS Name         : $CYMRU_ASNAME"
            echo "Country         : $CYMRU_CC"
            echo "Registry        : $CYMRU_REGISTRY"
            echo "Allocated       : $CYMRU_ALLOCATED"
        else
            echo "(unavailable)"
        fi
        echo
        echo "------------------------------------------------------------"
        echo "INVESTIGATION SUMMARY"
        echo "------------------------------------------------------------"
        if [[ "$VT_MALICIOUS" -gt 0 ]]; then
            printf '%b\n' "${RED}VirusTotal       : MALICIOUS INDICATOR DETECTED${NC}"
        else
            printf '%b\n' "${GREEN}VirusTotal       : No malicious detections${NC}"
        fi
        if [[ "$ABUSE_SCORE" -ge 70 ]]; then
            printf '%b\n' "${RED}AbuseIPDB        : HIGH ABUSE CONFIDENCE${NC}"
        elif [[ "$ABUSE_SCORE" -ge 20 ]]; then
            printf '%b\n' "${YELLOW}AbuseIPDB        : SUSPICIOUS${NC}"
        else
            printf '%b\n' "${GREEN}AbuseIPDB        : LOW/NO ABUSE CONFIDENCE${NC}"
        fi
        if [[ "$GN_CLASSIFICATION" == "malicious" ]]; then
            printf '%b\n' "${RED}GreyNoise        : MALICIOUS${NC}"
        elif [[ "$GN_CLASSIFICATION" == "suspicious" ]]; then
            printf '%b\n' "${YELLOW}GreyNoise        : SUSPICIOUS${NC}"
        else
            echo "GreyNoise        : $GN_CLASSIFICATION"
        fi
        if [[ "$OTX_PULSES" -gt 0 ]]; then
            printf '%b\n' "${YELLOW}AlienVault OTX   : $OTX_PULSES PULSE(S) FOUND${NC}"
        else
            printf '%b\n' "${GREEN}AlienVault OTX   : No pulses found${NC}"
        fi
        if [[ "$IDB_VULN_COUNT" -gt 0 ]]; then
            printf '%b\n' "${RED}Shodan InternetDB: $IDB_VULN_COUNT KNOWN CVE(S)${NC}"
        else
            printf '%b\n' "${GREEN}Shodan InternetDB: No known CVEs${NC}"
        fi
        if [[ "$BLOCKLIST_COUNT" -ge 1 ]]; then
            printf '%b\n' "${RED}Blocklists       : $BLOCKLIST_COUNT of 3 LISTED (Spamhaus/SpamCop/Barracuda)${NC}"
        else
            printf '%b\n' "${GREEN}Blocklists       : Not listed on any of 3${NC}"
        fi
        echo
        if [[ "$IP_MALICIOUS" == "true" ]]; then
            printf '%b\n' "${RED}${BOLD}FINAL OUTCOME    : CONFIRMED MALICIOUS ACTIVITY${NC}"
        else
            printf '%b\n' "${GREEN}FINAL OUTCOME    : $SEVERITY${NC}"
        fi
        echo
        echo "============================================================"
    } > "$REPORT"
    echo
    ok "Text report saved: $REPORT"
    [[ -n "$REPORT_DIR_OWNER" ]] && chown "${REPORT_DIR_OWNER}:${REPORT_DIR_OWNER}" "$REPORT" 2>/dev/null
    # ========================================================
    # HTML REPORT GENERATION (additive; never blocks/alters the
    # scan result, scoring, TXT report, or exit code)
    # ========================================================
    local REPORT_HTML="${HTML_REPORT_DIR}/IP_${SAFE_IP}_${TIMESTAMP}.html"
    if [[ -n "$RENDER_HTML_SCRIPT" && -f "$RENDER_HTML_SCRIPT" ]]; then
        grep -iE \
            '^[[:space:]]*(inetnum|NetRange|CIDR|route|origin|originAS|netname|NetName|OrgName|org-name|country|Country|created|last-modified|RegDate|Updated|OrgAbuseEmail|abuse-c|mnt-by|status):' \
            "$TMP/whois.txt" 2>/dev/null |
            awk '!seen[$0]++' |
            head -n 100 > "$TMP/whois_filtered.txt" || : > "$TMP/whois_filtered.txt"

        if jq empty "$TMP/rdap.json" >/dev/null 2>&1 &&
           jq -e '.objectClassName' "$TMP/rdap.json" >/dev/null 2>&1; then
            jq -r '
                def values_for_role($role; $field):
                    [
                        .. |
                        objects |
                        select((.roles? // []) | index($role)) |
                        .vcardArray[1][]? |
                        select(.[0] == $field) |
                        .[3]
                    ] | flatten | map(select(. != null and . != "")) | unique;
                def first_value($arr; $default):
                    if ($arr | length) > 0 then $arr[0] else $default end;
                (first_value(values_for_role("registrant"; "org") + values_for_role("registrant"; "fn"); "Unknown")) as $registrant |
                (first_value(values_for_role("abuse"; "email"); "Not listed")) as $abuse |
                ((.cidr0_cidrs // []) | map("\(.v4prefix // .v6prefix // "?")/\(.length // "?")") | join(", ")) as $cidr |
                "Network Name : \(.name // "Unknown")",
                "IP Range     : \(.startAddress // "?") - \(.endAddress // "?")",
                "CIDR         : \($cidr)",
                "Reg. Type    : \(.type // "Unknown")",
                "Registrant   : \($registrant)",
                "Abuse Email  : \($abuse)"
            ' "$TMP/rdap.json" > "$TMP/rdap_filtered.txt" 2>/dev/null || echo "(could not parse RDAP data)" > "$TMP/rdap_filtered.txt"
        else
            echo "(unavailable)" > "$TMP/rdap_filtered.txt"
        fi

        : > "$TMP/findings.jsonl"
        for item in "${FINDINGS[@]:-}"; do
            [[ -z "$item" ]] && continue
            local flevel="warn"
            case "$item" in
                *malicious*|*MALICIOUS*|*detections*|*detection.*|*escalated*|*Spamhaus*)
                    flevel="bad" ;;
            esac
            jq -n --arg text "$item" --arg level "$flevel" '{text:$text, level:$level}' >> "$TMP/findings.jsonl" 2>/dev/null
        done
        jq -s '.' "$TMP/findings.jsonl" > "$TMP/findings.json" 2>/dev/null || echo '[]' > "$TMP/findings.json"

        : > "$TMP/config_warnings.jsonl"
        [[ "$VT_CONFIGURED" == "false" ]] && jq -n '{text:"VirusTotal was not checked — treat as UNKNOWN, not clean."}' >> "$TMP/config_warnings.jsonl" 2>/dev/null
        [[ "$ABUSE_CONFIGURED" == "false" ]] && jq -n '{text:"AbuseIPDB was not checked — treat as UNKNOWN, not clean."}' >> "$TMP/config_warnings.jsonl" 2>/dev/null
        [[ "$OTX_CONFIGURED" == "false" ]] && jq -n '{text:"AlienVault OTX was not checked — treat as UNKNOWN, not clean."}' >> "$TMP/config_warnings.jsonl" 2>/dev/null
        [[ "$GN_QUERY_OK" != "true" ]] && jq -n --arg h "$GN_HTTP" '{text:("GreyNoise was not successfully queried (HTTP " + $h + ") — treat as UNKNOWN, not clean.")}' >> "$TMP/config_warnings.jsonl" 2>/dev/null
        jq -s '.' "$TMP/config_warnings.jsonl" > "$TMP/config_warnings.json" 2>/dev/null || echo '[]' > "$TMP/config_warnings.json"

        : > "$TMP/sources.jsonl"
        add_src() {
            local name="$1" okflag="$2" note="${3:-}"
            jq -n --arg name "$name" \
                  --argjson ok "$( [[ "$okflag" == "true" ]] && echo true || echo false )" \
                  --arg note "$note" \
                  '{name:$name, ok:$ok, note:$note}' >> "$TMP/sources.jsonl" 2>/dev/null
        }
        add_src "RDAP" "$RDAP_OK" ""
        add_src "Reverse DNS" "$RDNS_OK" "$( [[ "$RDNS_OK" == "false" ]] && echo 'No PTR record — often normal' )"
        add_src "WHOIS" "$WHOIS_OK" ""
        add_src "IPinfo" "$IPINFO_OK" ""
        add_src "Team Cymru ASN" "$CYMRU_CONFIGURED" ""
        add_src "VirusTotal" "$VT_CONFIGURED" "$( [[ -z "$VT_API_KEY" ]] && echo 'No API key configured' )"
        add_src "AbuseIPDB" "$ABUSE_CONFIGURED" "$( [[ -z "$ABUSEIPDB_API_KEY" ]] && echo 'No API key configured' )"
        add_src "GreyNoise" "$( [[ "$GN_QUERY_OK" == "true" ]] && echo true || echo false )" "$( [[ "$GN_QUERY_OK" != "true" ]] && echo "HTTP $GN_HTTP" )"
        add_src "AlienVault OTX" "$OTX_CONFIGURED" ""
        add_src "Shodan InternetDB" "$IDB_CONFIGURED" "IPv6 or no scan data on file"
        add_src "Spamhaus ZEN" "$SPAMHAUS_CONFIGURED" ""
        add_src "SpamCop" "$SPAMCOP_CONFIGURED" ""
        add_src "Barracuda" "$BARRACUDA_CONFIGURED" ""
        unset -f add_src
        jq -s '.' "$TMP/sources.jsonl" > "$TMP/sources.json" 2>/dev/null || echo '[]' > "$TMP/sources.json"

        jq -n --arg ip "$IP" --arg asn "$CYMRU_ASN" '
            [
                {label:"VirusTotal", url:("https://www.virustotal.com/gui/ip-address/" + $ip)},
                {label:"AbuseIPDB", url:("https://www.abuseipdb.com/check/" + $ip)},
                {label:"GreyNoise", url:("https://viz.greynoise.io/ip/" + $ip)},
                {label:"Shodan", url:("https://www.shodan.io/host/" + $ip)},
                {label:"Shodan InternetDB", url:("https://internetdb.shodan.io/" + $ip)},
                {label:"Censys", url:("https://search.censys.io/hosts/" + $ip)},
                {label:"AlienVault OTX", url:("https://otx.alienvault.com/indicator/ip/" + $ip)},
                {label:"URLScan", url:("https://urlscan.io/search/#ip:" + $ip)},
                {label:"Cisco Talos", url:("https://talosintelligence.com/reputation_center/lookup?search=" + $ip)},
                {label:"ThreatFox", url:("https://threatfox.abuse.ch/browse.php?search=" + $ip)},
                {label:"Feodo Tracker", url:("https://feodotracker.abuse.ch/browse.php?search=" + $ip)},
                {label:"IPinfo", url:("https://ipinfo.io/" + $ip)},
                {label:"BGP HE", url:("https://bgp.he.net/ip/" + $ip)},
                {label:"ARIN RDAP", url:("https://search.arin.net/rdap/?query=" + $ip)},
                {label:"Spamhaus IP Reputation", url:("https://check.spamhaus.org/results/?searchterm=" + $ip)},
                {label:"SpamCop", url:("https://www.spamcop.net/w3m?action=checkblock&ip=" + $ip)},
                {label:"Barracuda", url:("https://www.barracudacentral.org/lookups?ip=" + $ip)}
            ] + (if $asn != "Unknown" and $asn != "" then [{label:"Team Cymru ASN", url:("https://asn.cymru.com/cgi-bin/whois.cgi?asn=" + $asn)}] else [] end)
        ' > "$TMP/links.json" 2>/dev/null || echo '[]' > "$TMP/links.json"

        jq -n \
            --arg ip "$IP" \
            --arg timestamp "$TIMESTAMP" \
            --arg version "$VERSION" \
            --argjson score "$SCORE" \
            --arg severity "$SEVERITY" \
            --argjson malicious "$( [[ "$IP_MALICIOUS" == "true" ]] && echo true || echo false )" \
            --arg org "$IPINFO_ORG" \
            --arg asn "$WHOIS_ASN" \
            --arg netname "$WHOIS_NETNAME" \
            --arg hostname "$IPINFO_HOSTNAME" \
            --arg rdns "$RDNS" \
            --arg country "$IPINFO_COUNTRY" \
            --arg region "$IPINFO_REGION" \
            --arg city "$IPINFO_CITY" \
            --arg usage "$ABUSE_USAGE" \
            --arg isp "$ABUSE_ISP" \
            --arg domain "$ABUSE_DOMAIN" \
            --arg cymru_asn "$CYMRU_ASN" \
            --arg cymru_asname "$CYMRU_ASNAME" \
            --arg cymru_cc "$CYMRU_CC" \
            --arg cymru_registry "$CYMRU_REGISTRY" \
            --arg cymru_allocated "$CYMRU_ALLOCATED" \
            --argjson cymru_ok "$( [[ "$CYMRU_CONFIGURED" == "true" && "$CYMRU_ASN" != "Unknown" ]] && echo true || echo false )" \
            --arg vt_line "$VT_REPORT_LINE" \
            --argjson vt_malicious "$VT_MALICIOUS" \
            --argjson vt_suspicious "$VT_SUSPICIOUS" \
            --arg abuse_line "$ABUSE_REPORT_LINE" \
            --argjson abuse_score "$ABUSE_SCORE" \
            --arg gn_class "$GN_CLASSIFICATION" \
            --arg gn_line1 "$GN_REPORT_LINE" \
            --arg gn_line2 "$GN_SECOND_LINE" \
            --arg otx_line "$OTX_REPORT_LINE" \
            --argjson otx_pulses "$OTX_PULSES" \
            --arg idb_line "$IDB_REPORT_LINE" \
            --argjson idb_vulns "$IDB_VULN_COUNT" \
            --arg idb_ports "$IDB_PORTS" \
            --arg idb_vulns_list "$IDB_VULNS" \
            --arg idb_tags "$IDB_TAGS" \
            --arg idb_hostnames "$IDB_HOSTNAMES" \
            --arg idb_cpes "$IDB_CPES" \
            --arg spamhaus_line "$SPAMHAUS_REPORT_LINE" \
            --argjson spamhaus_listed "$( [[ "$SPAMHAUS_LISTED" == "true" ]] && echo true || echo false )" \
            --argjson spamcop_listed "$( [[ "$SPAMCOP_LISTED" == "true" ]] && echo true || echo false )" \
            --argjson barracuda_listed "$( [[ "$BARRACUDA_LISTED" == "true" ]] && echo true || echo false )" \
            --argjson blocklist_count "$BLOCKLIST_COUNT" \
            --rawfile whois_raw "$TMP/whois_filtered.txt" \
            --rawfile rdap_raw "$TMP/rdap_filtered.txt" \
            --slurpfile findings "$TMP/findings.json" \
            --slurpfile config_warnings "$TMP/config_warnings.json" \
            --slurpfile sources "$TMP/sources.json" \
            --slurpfile links "$TMP/links.json" \
            '{
                ip: $ip, timestamp: $timestamp, version: $version,
                score: $score, severity: $severity, malicious: $malicious,
                network: {org:$org, asn:$asn, netname:$netname, hostname:$hostname, rdns:$rdns, country:$country, region:$region, city:$city, usage:$usage, isp:$isp, domain:$domain},
                cymru: {ok:$cymru_ok, asn:$cymru_asn, asname:$cymru_asname, country:$cymru_cc, registry:$cymru_registry, allocated:$cymru_allocated},
                intel: {
                    vt: {line:$vt_line, malicious:$vt_malicious, suspicious:$vt_suspicious},
                    abuse: {line:$abuse_line, score:$abuse_score},
                    gn: {classification:$gn_class, line1:$gn_line1, line2:$gn_line2},
                    otx: {line:$otx_line, pulses:$otx_pulses},
                    idb: {line:$idb_line, vulns:$idb_vulns, ports:$idb_ports, vuln_list:$idb_vulns_list, tags:$idb_tags, hostnames:$idb_hostnames, cpes:$idb_cpes},
                    spamhaus: {line:$spamhaus_line, listed:$spamhaus_listed},
                    spamcop: {listed:$spamcop_listed},
                    barracuda: {listed:$barracuda_listed},
                    blocklist_count: $blocklist_count
                },
                whois_raw: $whois_raw,
                rdap_raw: $rdap_raw,
                findings: $findings[0],
                config_warnings: $config_warnings[0],
                sources: $sources[0],
                links: $links[0]
            }' > "$TMP/report_data.json" 2>"$TMP/jq_err.txt"

        if [[ -s "$TMP/report_data.json" ]] && jq empty "$TMP/report_data.json" >/dev/null 2>&1; then
            if python3 "$RENDER_HTML_SCRIPT" "$TMP/report_data.json" "$REPORT_HTML" 2>"$TMP/html_err.txt"; then
                ok "HTML report saved : $REPORT_HTML"
                [[ -n "$REPORT_DIR_OWNER" ]] && chown "${REPORT_DIR_OWNER}:${REPORT_DIR_OWNER}" "$REPORT_HTML" 2>/dev/null
            else
                warn "HTML report generation failed (TXT report above is unaffected)"
                [[ -s "$TMP/html_err.txt" ]] && sed 's/^/    /' "$TMP/html_err.txt"
            fi
        else
            warn "HTML report data could not be assembled; skipping HTML report for this IP (TXT report is unaffected)"
        fi
    else
        warn "HTML renderer unavailable this session; skipping HTML report for this IP (TXT report is unaffected)"
    fi
    echo
    case "$SEVERITY" in
        CRITICAL)
            echo -e "${RED}${BOLD}============================================================${NC}"
            echo -e "${RED}${BOLD} CRITICAL RISK: MALICIOUS INDICATORS DETECTED${NC}"
            echo -e "${RED}${BOLD}============================================================${NC}"
            ;;
        HIGH)
            echo -e "${RED}${BOLD}============================================================${NC}"
            echo -e "${RED}${BOLD} HIGH RISK: STRONG MALICIOUS INDICATORS DETECTED${NC}"
            echo -e "${RED}${BOLD}============================================================${NC}"
            ;;
        MEDIUM)
            echo -e "${YELLOW}${BOLD}============================================================${NC}"
            echo -e "${YELLOW}${BOLD} MEDIUM RISK: SUSPICIOUS INDICATORS DETECTED${NC}"
            echo -e "${YELLOW}${BOLD}============================================================${NC}"
            ;;
        LOW)
            echo -e "${GREEN}============================================================${NC}"
            echo -e "${GREEN} LOW RISK: No strong malicious indicators detected${NC}"
            echo -e "${GREEN}============================================================${NC}"
            ;;
    esac
    echo
}
# ============================================================
# SESSION SUMMARY (printed once, at the very end)
# ============================================================
print_session_summary() {
    local i sev ip score mal
    section "SESSION SUMMARY"
    for i in "${!SESSION_IPS[@]}"; do
        ip="${SESSION_IPS[$i]}"
        sev="${SESSION_SEVERITIES[$i]}"
        score="${SESSION_SCORES[$i]}"
        mal="${SESSION_MALICIOUS[$i]}"
        if [[ "$mal" == "true" ]]; then
            printf '%b\n' "${RED}${BOLD}  [MALICIOUS] $ip  — score $score/100, severity $sev${NC}"
        else
            case "$sev" in
                MEDIUM) printf '%b\n' "${YELLOW}  [$sev]      $ip  — score $score/100${NC}" ;;
                *)      printf '%b\n' "${GREEN}  [$sev]      $ip  — score $score/100${NC}" ;;
            esac
        fi
    done
    echo
    if [[ "$ANY_MALICIOUS" -eq 1 ]]; then
        echo -e "${RED}${BOLD}############################################################${NC}"
        echo -e "${RED}${BOLD}#  SESSION RESULT: MALICIOUS ACTIVITY DETECTED THIS SESSION${NC}"
        echo -e "${RED}${BOLD}#  At least one scanned IP had a confirmed malicious${NC}"
        echo -e "${RED}${BOLD}#  indicator from VirusTotal, AbuseIPDB, GreyNoise, or Spamhaus.${NC}"
        echo -e "${RED}${BOLD}############################################################${NC}"
    elif [[ "$WORST_EXIT" -ge 1 ]]; then
        echo -e "${YELLOW}${BOLD}============================================================${NC}"
        echo -e "${YELLOW}${BOLD}  SESSION RESULT: SUSPICIOUS INDICATORS FOUND, NONE CONFIRMED${NC}"
        echo -e "${YELLOW}${BOLD}============================================================${NC}"
    else
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN}  SESSION RESULT: NO MALICIOUS ACTIVITY DETECTED${NC}"
        echo -e "${GREEN}============================================================${NC}"
    fi
    echo
}
# ============================================================
# BATCH MODE
#
# Scans every IP listed in a file (one per line; blank lines and
# lines starting with '#' are skipped), back-to-back, then prints
# one session summary and exits with the worst severity seen —
# useful for scanning a watchlist/blocklist from cron or CI.
# ============================================================
if [[ -n "$BATCH_FILE" ]]; then
    if [[ ! -f "$BATCH_FILE" ]]; then
        bad "Batch file not found: $BATCH_FILE"
        exit 1
    fi
    info "Batch mode: reading IPs from $BATCH_FILE"
    BATCH_LINE_NUM=0
    BATCH_SCANNED=0
    BATCH_SKIPPED=0
    while IFS= read -r BATCH_LINE || [[ -n "$BATCH_LINE" ]]; do
        BATCH_LINE_NUM=$((BATCH_LINE_NUM + 1))
        BATCH_LINE="$(echo "${BATCH_LINE:-}" | sed 's/#.*$//' | xargs 2>/dev/null || true)"
        [[ -z "$BATCH_LINE" ]] && continue
        if is_valid_ip "$BATCH_LINE"; then
            scan_ip "$BATCH_LINE"
            BATCH_SCANNED=$((BATCH_SCANNED + 1))
        else
            bad "Line $BATCH_LINE_NUM: invalid IP address, skipping: $BATCH_LINE"
            BATCH_SKIPPED=$((BATCH_SKIPPED + 1))
        fi
    done < "$BATCH_FILE"
    info "Batch complete: $BATCH_SCANNED scanned, $BATCH_SKIPPED skipped (invalid)."
    print_session_summary
    exit "$WORST_EXIT"
fi
# ============================================================
# SINGLE-IP MODE
# ============================================================
if [[ -n "$CLI_IP" ]]; then
    if is_valid_ip "$CLI_IP"; then
        scan_ip "$CLI_IP"
        print_session_summary
        exit "$WORST_EXIT"
    else
        bad "Invalid IP address: $CLI_IP"
        exit 1
    fi
fi
# ============================================================
# SCAN HISTORY BROWSER
# ============================================================
show_history() {
    local files
    mapfile -t files < <(ls -t "$TEXT_REPORT_DIR"/IP_*.txt 2>/dev/null | head -n 20)
    if [[ "${#files[@]}" -eq 0 ]]; then
        warn "No previous scan reports found in $TEXT_REPORT_DIR"
        return
    fi
    local ESC
    ESC=$'\x1b'
    section "SCAN HISTORY (most recent ${#files[@]})"
    local i=1
    local f ip_from_name sev score html_sibling
    for f in "${files[@]}"; do
        ip_from_name="$(basename "$f" | sed -E 's/^IP_(.+)_[0-9]{8}T[0-9]{6}Z\.txt$/\1/' | tr '_' ':')"
        # Strip ANSI colour codes BEFORE the anchored grep — the raw
        # report lines start with an escape sequence (e.g. "\e[0;32m")
        # ahead of the text, so grep '^Severity' would never match if
        # stripping happened after extraction, as it did previously.
        sev="$(sed "s/${ESC}\[[0-9;]*m//g" "$f" 2>/dev/null | grep -m1 '^Severity' | sed -E 's/^Severity[[:space:]]*: *//')"
        score="$(sed "s/${ESC}\[[0-9;]*m//g" "$f" 2>/dev/null | grep -m1 '^Risk Score' | grep -oE '[0-9]+ / 100' | awk '{print $1}')"
        # HTML siblings live in a separate directory now, same basename
        # with a .html extension instead of .txt.
        html_sibling="${HTML_REPORT_DIR}/$(basename "${f%.txt}.html")"
        if [[ -f "$html_sibling" ]]; then
            printf '  %2d) %-20s severity=%-10s score=%s/100  [html available]\n' "$i" "$ip_from_name" "${sev:-?}" "${score:-?}"
        else
            printf '  %2d) %-20s severity=%-10s score=%s/100\n' "$i" "$ip_from_name" "${sev:-?}" "${score:-?}"
        fi
        i=$((i + 1))
    done
    echo
    local SEL
    read -rp "Enter a number to view that report, or press Enter to go back: " SEL
    if [[ "$SEL" =~ ^[0-9]+$ ]] && [[ "$SEL" -ge 1 ]] && [[ "$SEL" -le "${#files[@]}" ]]; then
        local chosen="${files[$((SEL - 1))]}"
        echo
        if command -v less >/dev/null 2>&1; then
            less -R "$chosen"
        else
            cat "$chosen"
        fi
    fi
    echo
}
# ============================================================
# INTERACTIVE LOOP
# ============================================================
while true; do
    echo
    read -rp "Enter IP address ('history' to browse past scans, 'quit' to stop): " IP
    IP="$(echo "${IP:-}" | xargs 2>/dev/null || true)"
    if [[ -z "$IP" ||
          "$IP" == "quit" ||
          "$IP" == "exit" ]]; then
        break
    fi
    if [[ "$IP" == "history" || "$IP" == "list" ]]; then
        show_history
        continue
    fi
    if ! is_valid_ip "$IP"; then
        bad "Invalid IP address: $IP"
        echo
        continue
    fi
    scan_ip "$IP"
    echo
    echo "------------------------------------------------------------"
done
# ============================================================
# SESSION COMPLETE
# ============================================================
echo
echo -e "${BOLD}${CYAN}============================================================${NC}"
echo -e "${BOLD}${CYAN}  Session complete.${NC}"
echo -e "${BOLD}${CYAN}  Text reports: $TEXT_REPORT_DIR${NC}"
echo -e "${BOLD}${CYAN}  HTML reports: $HTML_REPORT_DIR${NC}"
echo -e "${BOLD}${CYAN}============================================================${NC}"
if [[ "${#SESSION_IPS[@]}" -gt 0 ]]; then
    print_session_summary
fi
exit "$WORST_EXIT"
