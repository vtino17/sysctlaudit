#!/usr/bin/env bash
# sysctlaudit tests. Read-only; fixtures in a temp dir.
set -uo pipefail
cd "$(dirname "$0")/.."
SA="python3 sysctlaudit.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
refute() {   # <desc> <needle> -- <cmd...>
    local desc="$1" needle="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then printf '  FAIL  %s (found %s)\n' "$desc" "$needle"; fail=$((fail+1))
    else printf '  PASS  %s\n' "$desc"; pass=$((pass+1)); fi
}
assert_exit() {  # <desc> <code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s want %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax =="
if python3 -c "import ast; ast.parse(open('sysctlaudit.py').read())"; then
    echo "  PASS  sysctlaudit.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi

echo "== wrong / missing values =="
printf 'net.ipv4.tcp_syncookies = 0\n' > "$T/bad.conf"
assert "wrong value is HIGH"      "is 0, should be 1"   -- $SA "$T/bad.conf" --no-color
assert "unset key warned"         "not set"             -- $SA "$T/bad.conf" --no-color
assert_exit "wrong value exits non-zero" 1 -- $SA "$T/bad.conf" --no-color

echo "== gte comparator (kptr_restrict=2 satisfies >=1) =="
printf 'kernel.kptr_restrict = 2\n' > "$T/gte.conf"
refute "kptr_restrict=2 not flagged wrong" "kernel.kptr_restrict: is" -- $SA "$T/gte.conf" --no-color

echo "== ip_forward context note =="
printf 'net.ipv4.ip_forward = 1\n' > "$T/fwd.conf"
assert "ip_forward on gets a note" "correct only if this host is a router" -- $SA "$T/fwd.conf" --no-color

echo "== a fully hardened config scores high and exits zero =="
cat > "$T/hard.conf" <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
assert "hardened scores 100"      "score: 100/100"      -- $SA "$T/hard.conf" --no-color
assert_exit "hardened exits zero" 0 -- $SA "$T/hard.conf" --no-color

echo "== directory + later-file-wins merge =="
mkdir -p "$T/d"
printf 'net.ipv4.tcp_syncookies = 0\n' > "$T/d/10-base.conf"
printf 'net.ipv4.tcp_syncookies = 1\n' > "$T/d/99-override.conf"
refute "later file overrides earlier" "tcp_syncookies: is 0" -- $SA "$T/d" --no-color

echo "== sysctl.d directory precedence =="
mkdir -p "$T/etc" "$T/vendor"
printf 'net.ipv4.tcp_syncookies = 1\n' > "$T/etc/50-security.conf"
printf 'net.ipv4.tcp_syncookies = 0\n' > "$T/vendor/50-security.conf"
if python3 - "$T/etc" "$T/vendor" <<'PY'
import os, sys, sysctlaudit
paths = sysctlaudit._resolve_default_targets([sys.argv[1], sys.argv[2]], os.path.join(sys.argv[1], "missing"))
assert paths == [os.path.join(sys.argv[1], "50-security.conf")]
PY
then printf '  PASS  %s\n' "higher-priority basename masks vendor file"; pass=$((pass+1))
else printf '  FAIL  %s\n' "higher-priority basename masks vendor file"; fail=$((fail+1)); fi

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
