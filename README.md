# Nano-OpenShell

A minimal, zero-external-daemon reference implementation (~1,000 lines of Python on Linux) of OpenShell's core sandbox security architecture: **Linux User/Network Namespace Isolation**, **Procfs Socket-to-Binary Attribution**, **Out-of-Process L4/Binary/L7 Policy Enforcement & Credential Injection**, and **Static Policy Containment Verification**.

## Architecture

```text
+-----------------------------------------------------------------------+
| Linux Isolated Sandbox (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)   |
|  - Zero host secrets in env (REAL_*, *_KEY, *_TOKEN scrubbed)         |
|  - Direct raw egress (e.g. 1.1.1.1:80) -> ENETUNREACH                 |
|                                                                       |
|  +-----------------------+     TCP (lo)     +----------------------+  |
|  | Workload Process      | ---------------> | sandbox.py Broker    |  |
|  | (python3 / curl / sh) |                  | /proc/self/net/tcp + |  |
|  +-----------------------+                  | /proc/<pid>/fd       |  |
|             ^                               +----------+-----------+  |
|             | SIGSTOP on disconnect                    |              |
+-------------|------------------------------------------|--------------+
              |                                          | Mediated UDS
              |                                          v
+-------------|---------------------------------------------------------+
| Host Trusted Boundary (supervisor.py)                                 |
|  1. Mediated Channel Handshake & Liveness Watchdog                    |
|  2. L4 (Host:Port) -> Per-Binary Identity -> L7 (Method + Path)       |
|  3. Out-of-Sandbox Credential Injection (Bearer ${REAL_OPENAI_KEY})   |
|  4. Structured Denial Aggregator -> denials.json & policy-proposal    |
+--------------------------------------------------------+--------------+
                                                         |
                                                         v
                                              +----------------------+
                                              | prover.py            |
                                              | Static Containment & |
                                              | Auto-Approval Gate   |
                                              +----------------------+
```

## Components

| File | Milestone | Responsibility |
|---|---|---|
| `policy.py` | Milestone 1 | L4 (`host:port`), Per-Binary (`realpath` / `sha256` / `/tmp` untrusted exec guard), and normalized L7 (`method` + `path`) policy evaluator |
| `policy.yaml` | Milestone 1 | Baseline declarative egress & credential injection policy |
| `supervisor.py` | Milestone 2 | Out-of-process UDS supervisor, mediated channel authentication, credential injection, and structured `DenialAggregator` |
| `sandbox.py` | Milestone 3 | Rootless Linux `CLONE_NEWUSER \| CLONE_NEWNET \| CLONE_NEWNS` isolation, `/proc` socket-to-binary observer, fail-closed startup handshake, and `SIGSTOP` disconnect watchdog |
| `prover.py` | Milestone 4 | Dependency-free static policy containment verifier blocking unsafe auto-approvals (`CLOUD_METADATA_GUARD`, `NEW_CREDENTIALED_REACH`, `UNAPPROVED_EGRESS_ENDPOINT`, `BINARY_PRIVILEGE_EXPANSION`, `L7_METHOD_PATH_WIDENING`) |
| `test_regression.sh` | E2E Suite | Automated 4-stage end-to-end regression suite with strict assertions |

## Prerequisites

- **OS**: Linux with unprivileged user namespaces enabled (`CLONE_NEWUSER` / `CLONE_NEWNET`)
- **Python**: Python 3.9+
- **Dependencies**: `PyYAML`

```shell
pip install -r requirements.txt
```

## Quickstart

### 1. Run the Full End-to-End Regression Suite

```shell
bash test_regression.sh
```

### 2. Interactive Walkthrough

Start the out-of-process Supervisor on the host with a secret key:

```shell
REAL_OPENAI_KEY="sk-live-secret-999" python3 supervisor.py
```

In another terminal, run workloads inside the isolated sandbox boundary:

```shell
# 1. Authorized Python agent request -> Allowed (HTTP 200) with Bearer token injected by Supervisor
python3 sandbox.py -- python3 -c '
import urllib.request
req = urllib.request.Request("http://api.openai.local:18080/v1/chat/completions", data=b"{}", method="POST")
print(urllib.request.urlopen(req).read().decode())
'

# 2. Unauthorized binary (/usr/bin/curl) inside the same sandbox -> Blocked (HTTP 403 BINARY_IDENTITY)
python3 sandbox.py -- curl -s -X POST http://api.openai.local:18080/v1/chat/completions

# 3. Audit the auto-generated policy proposal before applying -> Blocked (FAIL [HIGH] BINARY_PRIVILEGE_EXPANSION)
python3 prover.py policy.yaml policy-proposal.yaml
```
