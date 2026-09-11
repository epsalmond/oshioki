#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=/work
STATE_ROOT=/run/oshioki-pam-spike
MODE_FILE="$STATE_ROOT/mode"
PAM_LOG="$STATE_ROOT/pam.log"
FINAL_LOG="$STATE_ROOT/final.log"
PASSWORD_FILE="$STATE_ROOT/fixture-password"

cleanup() {
    rm -f "$PASSWORD_FILE"
}
trap cleanup EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq gcc libpam0g-dev python3 sudo >/dev/null

PAM_MODULE_PATH="$(dpkg-query -L libpam-modules | awk '$0 ~ /\/pam_unix\.so$/ { print; exit }')"
[ -n "$PAM_MODULE_PATH" ] || { echo 'could not locate pam_unix.so' >&2; exit 1; }
PAM_MODULE_DIR="$(dirname "$PAM_MODULE_PATH")"

gcc -std=c11 -Wall -Wextra -Werror -fPIC -shared \
    -Wl,-z,relro,-z,now \
    -o "$PAM_MODULE_DIR/pam_oshioki_spike.so" \
    "$WORKSPACE/tests/pam-spike/pam_oshioki_spike.c" \
    -lpam
gcc -std=c11 -Wall -Wextra -Werror -Wpedantic \
    -o /usr/local/bin/pam-spike-final \
    "$WORKSPACE/tests/pam-spike/final_probe.c"
ln -sf /usr/local/bin/pam-spike-final /usr/local/bin/pam-spike-nopass
ln -sf /usr/local/bin/pam-spike-final /usr/local/bin/pam-spike-pass

printf '%s\n' 'fixture-only-password' >"$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"
useradd --create-home --shell /bin/bash fixture
{ printf 'fixture:'; tr -d '\r\n' <"$PASSWORD_FILE"; printf '\n'; } | chpasswd

cat >/etc/pam.d/sudo <<EOF
# Test-only service: no include of common-auth or any host PAM stack.
auth [success=done authinfo_unavail=ignore default=die] pam_oshioki_spike.so mode_file=$MODE_FILE log_file=$PAM_LOG
auth required pam_unix.so
account required pam_oshioki_spike.so log_file=$PAM_LOG
account required pam_unix.so
EOF

if grep -Fq pam_oshioki_spike.so /etc/pam.d/common-auth; then
    echo 'PAM spike module leaked into common-auth' >&2
    exit 1
fi

cat >/etc/sudoers.d/pam-migration-spike <<'EOF'
Defaults timestamp_timeout=5
fixture ALL=(root) NOPASSWD: /usr/local/bin/pam-spike-nopass
fixture ALL=(root) PASSWD: /usr/local/bin/pam-spike-pass
EOF
chmod 0440 /etc/sudoers.d/pam-migration-spike
visudo -c >/dev/null

set_mode() {
    printf '%s\n' "$1" >"$MODE_FILE"
}

clear_observations() {
    : >"$PAM_LOG"
    : >"$FINAL_LOG"
}

auth_count() {
    awk '$0 ~ /^call=auth / { count++ } END { print count + 0 }' "$PAM_LOG"
}

final_count() {
    awk '$0 ~ /^pid=/ { count++ } END { print count + 0 }' "$FINAL_LOG"
}

run_case() {
    local name="$1"
    local mode="$2"
    local expected_prompt="$3"
    local expected_rc="$4"
    shift 4

    set_mode "$mode"
    clear_observations
    local result
    result="$(python3 "$WORKSPACE/tests/pam-spike/pty_sudo.py" \
        --password-file "$PASSWORD_FILE" \
        --expect-prompt "$expected_prompt" -- "$@")"
    local actual_rc actual_prompt
    actual_rc="$(printf '%s\n' "$result" | sed -n 's/^PTY_RC=//p')"
    actual_prompt="$(printf '%s\n' "$result" | sed -n 's/^PTY_PROMPT=//p')"
    [ "$actual_rc" = "$expected_rc" ] || {
        echo "FAIL: $name expected sudo rc=$expected_rc, got $actual_rc" >&2
        exit 1
    }
    echo "* PASS: $name (mode=$mode prompt=$actual_prompt rc=$actual_rc auth=$(auth_count) final=$(final_count))"
}

runuser_sudo_k() {
    runuser -u fixture -- sudo -k
}

# The NOPASSWD exception is narrow: it approves one exact helper while a
# PASSWD command still requires the configured PAM service.
runuser_sudo_k
run_case nopasswd-bypass approve no 0 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo -n \
    /usr/local/bin/pam-spike-nopass nopass --synthetic
[ "$(auth_count)" -eq 0 ] || { echo 'NOPASSWD unexpectedly invoked PAM' >&2; exit 1; }
[ "$(final_count)" -eq 1 ] || { echo 'NOPASSWD did not reach final exec' >&2; exit 1; }

runuser_sudo_k
run_case passwd-noninteractive-no-timestamp approve no 1 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo -n \
    /usr/local/bin/pam-spike-pass blocked
[ "$(auth_count)" -eq 0 ] || { echo 'sudo -n invoked PAM unexpectedly' >&2; exit 1; }
[ "$(final_count)" -eq 0 ] || { echo 'PASSWD command ran despite sudo -n' >&2; exit 1; }

# A successful test module decision completes auth without asking for a
# password, then account management and the final synthetic command run.
runuser_sudo_k
run_case pam-approve approve no 0 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo \
    /usr/local/bin/pam-spike-pass alpha 'world with spaces' --flag=beta
[ "$(auth_count)" -eq 1 ] || { echo 'approve did not invoke PAM once' >&2; exit 1; }
grep -Fq 'call=auth mode=approve service=sudo user=fixture' "$PAM_LOG"
grep -Fq 'euid=0' "$FINAL_LOG"

# PAM_AUTH_ERR follows the default=die action. A correct password cannot
# rescue the explicit denial, and no final command is executed.
runuser_sudo_k
run_case pam-deny deny no 1 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo \
    /usr/local/bin/pam-spike-pass denied
[ "$(final_count)" -eq 0 ] || { echo 'deny reached final exec' >&2; exit 1; }
deny_auth_count="$(auth_count)"
[ "$deny_auth_count" -ge 1 ] || { echo 'deny did not invoke PAM' >&2; exit 1; }

# PAM_AUTHINFO_UNAVAIL is ignored by the first stack entry, so pam_unix gets
# the normal password conversation and the command succeeds.
runuser_sudo_k
run_case pam-unavailable unavailable yes 0 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo \
    /usr/local/bin/pam-spike-pass unavailable
[ "$(auth_count)" -eq 1 ] || { echo 'unavailable did not invoke PAM once' >&2; exit 1; }
[ "$(final_count)" -eq 1 ] || { echo 'unavailable did not reach final exec' >&2; exit 1; }
cp "$PAM_LOG" "$STATE_ROOT/pam-example.log"
cp "$FINAL_LOG" "$STATE_ROOT/final-example.log"

# Keep both sudo invocations on the same PTY: the second uses the timestamp
# from the first and therefore skips PAM even after the mode changes to deny.
runuser_sudo_k
set_mode unavailable
clear_observations
timestamp_result="$(python3 "$WORKSPACE/tests/pam-spike/pty_sudo.py" \
    --password-file "$PASSWORD_FILE" --expect-prompt yes -- \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sh -c \
    'sudo /usr/local/bin/pam-spike-pass first; sudo -n /usr/local/bin/pam-spike-pass second')"
timestamp_rc="$(printf '%s\n' "$timestamp_result" | sed -n 's/^PTY_RC=//p')"
timestamp_prompt="$(printf '%s\n' "$timestamp_result" | sed -n 's/^PTY_PROMPT=//p')"
[ "$timestamp_rc" = 0 ] || { echo "timestamp reuse failed: $timestamp_result" >&2; exit 1; }
[ "$timestamp_prompt" = 1 ] || { echo "timestamp first auth prompt missing: $timestamp_result" >&2; exit 1; }
[ "$(auth_count)" -eq 1 ] || { echo 'timestamp reuse invoked PAM twice' >&2; exit 1; }
[ "$(final_count)" -eq 2 ] || { echo 'timestamp sequence did not execute twice' >&2; exit 1; }
echo "* PASS: timestamp reuse (first prompt=$timestamp_prompt rc=$timestamp_rc auth=$(auth_count) final=$(final_count))"

# sudo -k invalidates the timestamp on the same PTY. With the default
# noninteractive_auth setting, sudo -n then refuses before PAM and never opens
# a password prompt.
set_mode unavailable
clear_observations
sudo_k_result="$(python3 "$WORKSPACE/tests/pam-spike/pty_sudo.py" \
    --password-file "$PASSWORD_FILE" --expect-prompt yes -- \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sh -c \
    'sudo /usr/local/bin/pam-spike-pass before-k; sudo -k; sudo -n /usr/local/bin/pam-spike-pass after-k')"
sudo_k_rc="$(printf '%s\n' "$sudo_k_result" | sed -n 's/^PTY_RC=//p')"
sudo_k_prompt="$(printf '%s\n' "$sudo_k_result" | sed -n 's/^PTY_PROMPT=//p')"
[ "$sudo_k_rc" = 1 ] || { echo "sudo -k sequence unexpectedly returned $sudo_k_rc" >&2; exit 1; }
[ "$sudo_k_prompt" = 1 ] || { echo "sudo -k first auth prompt missing: $sudo_k_result" >&2; exit 1; }
[ "$(auth_count)" -eq 1 ] || { echo 'sudo -k sequence invoked PAM after -n' >&2; exit 1; }
[ "$(final_count)" -eq 1 ] || { echo 'sudo -k sequence did not run first command' >&2; exit 1; }
echo "* PASS: sudo-k-noninteractive (first prompt=$sudo_k_prompt rc=$sudo_k_rc auth=$(auth_count) final=$(final_count))"

runuser_sudo_k
run_case sudo-k-restores-password unavailable yes 0 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo \
    /usr/local/bin/pam-spike-pass after-k-password
[ "$(auth_count)" -eq 1 ] || { echo 'sudo -k did not require PAM again' >&2; exit 1; }

# A policy-denied command never reaches final exec; sudo may call PAM first.
runuser_sudo_k
run_case policy-denied approve any 1 \
    runuser -u fixture -- env PAM_SPIKE_MARKER=caller sudo /usr/bin/id
[ "$(final_count)" -eq 0 ] || { echo 'policy-denied command reached final exec' >&2; exit 1; }

echo "* PAM auth calls for explicit deny: $deny_auth_count"
echo '* PAM metadata (no password values):'
sed -n '1,40p' "$STATE_ROOT/pam-example.log"
echo '* final-exec metadata (synthetic argv/env only):'
sed -n '1,40p' "$STATE_ROOT/final-example.log"
