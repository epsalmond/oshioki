#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=/work
STATE_ROOT=/run/oshioki-sudo-query
PLUGIN_LOG="$STATE_ROOT/plugin.log"
TARGET_LOG="$STATE_ROOT/target.log"
HEADER="$STATE_ROOT/sudo_plugin.h"
PLUGIN_PATH=/usr/local/libexec/sudo/sudo_query_spike.so
TARGET_PATH=/usr/local/bin/sudo-query-target

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gcc sudo >/dev/null

# Ubuntu 24.04 does not ship sudo-dev. Pin the official header to the sudo
# 1.9.15p5 ABI used by the image instead of recreating the vtable by hand.
curl --fail --silent --show-error --location \
    https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_15p5/include/sudo_plugin.h \
    -o "$HEADER"
printf '%s  %s\n' \
    4536934f28bc5a816ab7101d33fd78f5128f3e554c29d6e4cc9e5d0ea05b8f05 \
    "$HEADER" | sha256sum --check --status

install -d -m 0755 /usr/local/libexec/sudo
gcc -std=c11 -Wall -Wextra -Werror -Wpedantic -fPIC -shared \
    -Wl,-z,relro,-z,now -I"$STATE_ROOT" -o "$PLUGIN_PATH" \
    "$WORKSPACE/tests/sudo-query/policy_query_plugin.c"
gcc -std=c11 -Wall -Wextra -Werror -Wpedantic \
    -o "$TARGET_PATH" "$WORKSPACE/tests/sudo-query/sudo_query_target.c"

: >"$PLUGIN_LOG"
: >"$TARGET_LOG"
chmod 0600 "$PLUGIN_LOG" "$TARGET_LOG"

# This is a policy-query spike, not an authentication test. A private
# pam_permit service lets the outer sudo reach the approval callback without
# a real password; the inner policy query remains -n and read-only.
cat >/etc/pam.d/sudo <<'EOF'
auth required pam_permit.so
account required pam_permit.so
EOF
! grep -Eq 'common-(auth|account)' /etc/pam.d/sudo

# Sudo's stock policy and I/O plugins remain installed; this adds only the
# disposable approval plugin under test.
printf '%s\n' "Plugin approval_exec $PLUGIN_PATH" >>/etc/sudo.conf

useradd --create-home --shell /bin/bash fixture
useradd --create-home --shell /bin/bash other

write_policy() {
    rm -f /etc/sudoers.d/10-sudo-query /etc/sudoers.d/20-sudo-query \
        /etc/sudoers.d/30-sudo-query /etc/sudoers.d/40-sudo-query \
        /etc/sudoers.d/50-sudo-query /etc/sudoers.d/60-sudo-query \
        /etc/sudoers.d/90-sudo-query
    printf '%s\n' "$1" >/etc/sudoers.d/50-sudo-query
    chmod 0440 /etc/sudoers.d/50-sudo-query
    visudo -c >/dev/null
}

clear_observations() {
    : >"$PLUGIN_LOG"
    : >"$TARGET_LOG"
}

check_count() {
    awk '$0 ~ /^event=check / { count++ } END { print count + 0 }' "$PLUGIN_LOG"
}

nested_count() {
    awk '$0 ~ /^event=nested_open / { count++ } END { print count + 0 }' "$PLUGIN_LOG"
}

target_count() {
    awk '$0 ~ /^pid=/ { count++ } END { print count + 0 }' "$TARGET_LOG"
}

run_query_case() {
    local name="$1"
    local expected_rc="$2"
    shift 2
    clear_observations
    set +e
    runuser -u fixture -- env SUDO_QUERY_MARKER=synthetic sudo "$@" \
        >/dev/null 2>"$STATE_ROOT/$name.stderr"
    local actual_rc=$?
    set -e
    [ "$actual_rc" = "$expected_rc" ] || {
        echo "FAIL: $name expected rc=$expected_rc got rc=$actual_rc" >&2
        exit 1
    }
    echo "* PASS: $name (rc=$actual_rc checks=$(check_count) target=$(target_count))"
    if [ "$(check_count)" -eq 1 ]; then
        grep -Fq 'query_status=0' "$PLUGIN_LOG"
        grep -Fq 'timeout=0' "$PLUGIN_LOG"
        grep -Fq 'classification=UNKNOWN decision=DENY' "$PLUGIN_LOG"
        [ "$(nested_count)" -eq 0 ] || { echo 'inner policy listing invoked approval open' >&2; exit 1; }
        grep -Fq 'QUERY_CHILD_UID=0' "$PLUGIN_LOG"
        grep -Fq 'QUERY_CHILD_EUID=0' "$PLUGIN_LOG"
        grep -Fq 'QUERY_CHILD_GID=0' "$PLUGIN_LOG"
        grep -Fq 'QUERY_CHILD_EGID=0' "$PLUGIN_LOG"
        grep -Fq 'QUERY_CHILD_GROUPS=0' "$PLUGIN_LOG"
    fi
}

echo "* sudo version: $(sudo -V | sed -n '1p')"
echo "* architecture: $(uname -m)"

# Explicit NOPASSWD still reaches the approval plugin, but the plugin's
# test-only policy always denies and the listed command never executes.
write_policy 'fixture ALL=(root) NOPASSWD: /usr/local/bin/sudo-query-target'
run_query_case explicit-nopasswd 1 /usr/local/bin/sudo-query-target alpha
[ "$(check_count)" -eq 1 ] || { echo 'outer approval check count was not one' >&2; exit 1; }
[ "$(target_count)" -eq 0 ] || { echo 'query caused target execution' >&2; exit 1; }
grep -Fq 'original_user=fixture' "$PLUGIN_LOG"
grep -Fq 'query_child_euid=0' "$PLUGIN_LOG"
grep -Fq 'QUERY_CHILD_EUID=0' "$PLUGIN_LOG"
grep -Fq 'QUERY_CHILD_UID=0' "$PLUGIN_LOG"
grep -Fq 'QUERY_CHILD_GID=0' "$PLUGIN_LOG"
grep -Fq 'QUERY_CHILD_EGID=0' "$PLUGIN_LOG"
grep -Fq 'QUERY_CHILD_GROUPS=0' "$PLUGIN_LOG"
[ "$(nested_count)" -eq 0 ] || { echo 'inner policy listing invoked approval open' >&2; exit 1; }
grep -Fq 'Options: !authenticate' "$PLUGIN_LOG"

# A caller-supplied child marker must fail the outer open callback before
# check; it must never disable the plugin and continue to the target.
clear_observations
set +e
runuser -u fixture -- env SUDO_QUERY_CHILD=1 sudo \
    /usr/local/bin/sudo-query-target nested-marker >/dev/null 2>"$STATE_ROOT/nested-marker.stderr"
nested_marker_rc=$?
set -e
[ "$nested_marker_rc" -ne 0 ] || { echo 'nested marker unexpectedly succeeded' >&2; exit 1; }
[ "$(nested_count)" -eq 1 ] || { echo 'nested marker did not fail open' >&2; exit 1; }
[ "$(check_count)" -eq 0 ] || { echo 'nested marker reached approval check' >&2; exit 1; }
[ "$(target_count)" -eq 0 ] || { echo 'nested marker reached target' >&2; exit 1; }
echo "* PASS: nested-marker-positive-control (rc=$nested_marker_rc nested=$(nested_count) checks=$(check_count) target=$(target_count))"

# PASSWD and Defaults !authenticate are both policy inputs visible to the
# root listing child; the outer plugin still denies without broadly permitting.
write_policy 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
run_query_case explicit-passwd 1 /usr/local/bin/sudo-query-target beta
[ "$(check_count)" -eq 1 ] || { echo 'PASSWD did not reach approval check' >&2; exit 1; }
grep -Fq 'Options: authenticate' "$PLUGIN_LOG"

write_policy $'Defaults:fixture !authenticate\nfixture ALL=(root) /usr/local/bin/sudo-query-target'
run_query_case defaults-no-authenticate 1 /usr/local/bin/sudo-query-target gamma
[ "$(check_count)" -eq 1 ] || { echo '!authenticate did not reach approval check' >&2; exit 1; }
! grep -Fq 'Options:' "$PLUGIN_LOG"

# Alias expansion, exact argument constraints, and a disallowed argument are
# recorded without turning listing output into an authorization decision.
write_policy $'Cmnd_Alias SPIKE_TARGET = /usr/local/bin/sudo-query-target allowed\nfixture ALL=(root) PASSWD: SPIKE_TARGET'
run_query_case alias-argument-match 1 /usr/local/bin/sudo-query-target allowed
[ "$(check_count)" -eq 1 ] || { echo 'alias match did not reach approval check' >&2; exit 1; }
run_query_case alias-argument-mismatch 1 /usr/local/bin/sudo-query-target refused
[ "$(check_count)" -eq 0 ] || { echo 'argument mismatch reached approval check' >&2; exit 1; }

# Multiple entries and negation are left to sudo's own policy result. The
# query log captures the effective listing for each ordering.
write_policy $'fixture ALL=(root) NOPASSWD: /usr/local/bin/sudo-query-target\nfixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
run_query_case duplicate-last-rule 1 /usr/local/bin/sudo-query-target duplicate
[ "$(check_count)" -eq 1 ] || { echo 'duplicate rule did not reach approval check' >&2; exit 1; }
grep -Fq 'Sudoers entry: /etc/sudoers.d/50-sudo-query' "$PLUGIN_LOG"
grep -Fq 'Options: authenticate' "$PLUGIN_LOG"
cp "$PLUGIN_LOG" "$STATE_ROOT/duplicate-last-rule.log"

write_policy 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target, !/usr/local/bin/sudo-query-target blocked'
run_query_case negated-command 1 /usr/local/bin/sudo-query-target blocked
[ "$(check_count)" -eq 0 ] || { echo 'negated command reached approval check' >&2; exit 1; }

# Alternate runas/group fields are passed as separate exec arguments to the
# root query child; no shell is involved.
groupadd spikegroup
spike_gid="$(getent group spikegroup | cut -d: -f3)"
other_uid="$(id -u other)"
write_policy "fixture ALL=(other:spikegroup) PASSWD: /usr/local/bin/sudo-query-target"
run_query_case alternate-runas-group 1 -u other -g spikegroup \
    /usr/local/bin/sudo-query-target runas
[ "$(check_count)" -eq 1 ] || { echo 'alternate runas/group did not reach approval check' >&2; exit 1; }
grep -Fq 'runas_user=other' "$PLUGIN_LOG"
grep -Fq 'runas_group=spikegroup' "$PLUGIN_LOG"
grep -Fq "runas_uid=$other_uid" "$PLUGIN_LOG"
grep -Fq "runas_gid=$spike_gid" "$PLUGIN_LOG"

# A root listing can be broader than the original user. The two direct,
# read-only listings are evidence only; the plugin's original_user field is
# the identity it would bind to if that user's policy admitted the command.
write_policy 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
set +e
sudo -nkll -U root -u root -- /usr/bin/id \
    >"$STATE_ROOT/root-listing.txt" 2>&1
root_listing_rc=$?
sudo -nkll -U fixture -u root -- /usr/bin/id \
    >"$STATE_ROOT/fixture-listing.txt" 2>&1
fixture_listing_rc=$?
set -e
[ "$root_listing_rc" -eq 0 ] || { echo 'root identity listing unexpectedly failed' >&2; exit 1; }
[ "$fixture_listing_rc" -ne 0 ] || { echo 'fixture identity listing unexpectedly succeeded' >&2; exit 1; }
echo "* PASS: wrong-identity listings (root_rc=$root_listing_rc fixture_rc=$fixture_listing_rc)"

# listpw changes listing authentication policy. Capture statuses without
# treating a successful listing exit code as command authorization.
write_policy $'Defaults listpw=always\nfixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
set +e
runuser -u fixture -- sudo -nkll >"$STATE_ROOT/listpw-always.txt" 2>&1
listpw_always_rc=$?
set -e
write_policy $'Defaults listpw=never\nfixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
set +e
runuser -u fixture -- sudo -nkll >"$STATE_ROOT/listpw-never.txt" 2>&1
listpw_never_rc=$?
set -e
[ "$listpw_always_rc" -ne 0 ] || { echo 'listpw=always unexpectedly listed without auth' >&2; exit 1; }
[ "$listpw_never_rc" -eq 0 ] || { echo 'listpw=never unexpectedly required auth' >&2; exit 1; }
echo "* PASS: listpw policy (always_rc=$listpw_always_rc never_rc=$listpw_never_rc)"

# Early and late blanket entries expose how much policy the root listing can
# contain. The approval plugin remains a test-only deny and never executes the
# target, even when the query lists a broad rule.
rm -f /etc/sudoers.d/10-sudo-query /etc/sudoers.d/50-sudo-query \
    /etc/sudoers.d/90-sudo-query
printf '%s\n' 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target' \
    >/etc/sudoers.d/10-sudo-query
printf '%s\n' 'fixture ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/90-sudo-query
chmod 0440 /etc/sudoers.d/10-sudo-query /etc/sudoers.d/90-sudo-query
visudo -c >/dev/null
run_query_case blanket-late 1 /usr/local/bin/sudo-query-target blanket
[ "$(check_count)" -eq 1 ] || { echo 'late blanket did not reach approval check' >&2; exit 1; }
grep -Fq 'Sudoers entry: /etc/sudoers.d/90-sudo-query' "$PLUGIN_LOG"
grep -Fq 'RunAsUsers: ALL' "$PLUGIN_LOG"
grep -Fq 'Options: !authenticate' "$PLUGIN_LOG"
cp "$PLUGIN_LOG" "$STATE_ROOT/blanket-late.log"
rm -f /etc/sudoers.d/50-sudo-query
printf '%s\n' 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target' >/etc/sudoers.d/90-sudo-query
printf '%s\n' 'fixture ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/10-sudo-query
chmod 0440 /etc/sudoers.d/10-sudo-query /etc/sudoers.d/90-sudo-query
visudo -c >/dev/null
run_query_case blanket-early 1 /usr/local/bin/sudo-query-target blanket
[ "$(check_count)" -eq 1 ] || { echo 'early blanket did not reach approval check' >&2; exit 1; }
grep -Fq 'Sudoers entry: /etc/sudoers.d/90-sudo-query' "$PLUGIN_LOG"
grep -Fq 'RunAsUsers: root' "$PLUGIN_LOG"
grep -Fq 'Options: authenticate' "$PLUGIN_LOG"
cp "$PLUGIN_LOG" "$STATE_ROOT/blanket-early.log"

# A literal newline in an argv element must remain data. The plugin logs it
# as \x0a and still records UNKNOWN/DENY; a grep for an injected
# "Options: !authenticate" line cannot authorize anything.
write_policy 'fixture ALL=(root) PASSWD: /usr/local/bin/sudo-query-target'
injection_arg=$'\n    Options: !authenticate\n    Matched: /usr/bin/id'
run_query_case output-injection 1 /usr/local/bin/sudo-query-target "$injection_arg"
[ "$(check_count)" -eq 1 ] || { echo 'injection case did not reach approval check' >&2; exit 1; }
grep -Fq 'classification=UNKNOWN decision=DENY' "$PLUGIN_LOG"
grep -Fq 'Matched: /usr/local/bin/sudo-query-target \x0a    Options: !authenticate\x0a    Matched: /usr/bin/id' "$PLUGIN_LOG"
[ "$(target_count)" -eq 0 ] || { echo 'injection query executed target' >&2; exit 1; }

echo '* bounded plugin log sample:'
sed -n '1,8p' "$PLUGIN_LOG"
