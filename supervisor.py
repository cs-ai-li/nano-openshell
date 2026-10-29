#!/usr/bin/env python3
"""
Nano-OpenShell Milestone 2: Out-of-Process Supervisor, Mediated Handshake,
Credential Injection & Structured Denial Aggregator.
"""
from __future__ import annotations

import copy
import fnmatch
import http.client
import http.server
import json
import os
import socket
import socketserver
import struct
import threading
import time
import urllib.parse
from typing import Any, Optional
import yaml

from policy import BinaryIdentity, PolicyEngine

DEFAULT_SOCK_PATH = "/tmp/nano-supervisor.sock"
DEFAULT_UPSTREAM_PORT = 18080
DEFAULT_CHANNEL_TOKEN = "nano-mediated-token-v1"
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


def get_peer_pid(sock: socket.socket) -> Optional[int]:
    """通过 Linux UDS SO_PEERCRED 获取直连客户端的内核可信 PID"""
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, _uid, _gid = struct.unpack("3i", creds)
        return pid if pid > 0 else None
    except OSError:
        return None


class DenialAggregator:
    """结构化拒绝感知聚合器与候选策略生成器 (对齐 openshell-sandbox/src/denial_aggregator.rs)"""

    def __init__(self, base_dir: str, baseline_policy: dict[str, Any]) -> None:
        self._lock = threading.Lock()
        self.denials_path = os.path.join(base_dir, "denials.json")
        self.proposal_path = os.path.join(base_dir, "policy-proposal.yaml")
        self.baseline = baseline_policy
        self.records: dict[tuple[str, str, int, str, str], dict[str, Any]] = {}

    def record(self, denial: dict[str, Any]) -> None:
        key = (
            denial["binary"],
            denial["host"],
            int(denial["port"]),
            denial["method"],
            denial["path"],
        )
        now_ts = int(time.time())
        with self._lock:
            if key in self.records:
                entry = self.records[key]
                entry["count"] += 1
                entry["last_seen"] = now_ts
            else:
                entry = {
                    **denial,
                    "count": 1,
                    "first_seen": now_ts,
                    "last_seen": now_ts,
                }
                self.records[key] = entry
            self._flush_locked()

    def _flush_locked(self) -> None:
        items = list(self.records.values())
        with open(self.denials_path, "w", encoding="utf-8") as f:
            json.dump({"denials": items}, f, indent=2, ensure_ascii=False)

        proposal = copy.deepcopy(self.baseline)
        rules: list[dict[str, Any]] = proposal.setdefault("network_policies", [])

        for d in items:
            host, port, binary, method, path = (
                d["host"],
                int(d["port"]),
                d["binary"],
                d["method"],
                d["path"],
            )
            matched_rule = None
            for r in rules:
                host_ok = any(fnmatch.fnmatch(host, h.lower()) for h in r.get("hosts", []))
                ports = r.get("ports", [])
                if host_ok and (not ports or port in ports):
                    matched_rule = r
                    break

            if matched_rule is not None:
                bins = matched_rule.setdefault("allowed_binaries", [])
                if binary not in bins:
                    bins.append(binary)
                l7s = matched_rule.setdefault("l7_rules", [])
                if not any(
                    method in l7.get("methods", []) and path in l7.get("paths", [])
                    for l7 in l7s
                ):
                    l7s.append({"methods": [method], "paths": [path]})
            else:
                safe_name = host.replace(".", "_").replace(":", "_")
                rules.append(
                    {
                        "name": f"proposed_{safe_name}_{port}",
                        "hosts": [host],
                        "ports": [port],
                        "allowed_binaries": [binary],
                        "l7_rules": [{"methods": [method], "paths": [path]}],
                    }
                )

        with open(self.proposal_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(proposal, f, sort_keys=False, allow_unicode=True)


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True


class SupervisorHandler(http.server.BaseHTTPRequestHandler):
    engine: PolicyEngine
    aggregator: DenialAggregator
    channel_token: str
    upstream_port: int

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[supervisor] {fmt % args}", flush=True)

    def _handle_all(self) -> None:
        # 1. Mediated Channel 鉴权：防止沙箱内进程绕过 sandbox.py 直连 UDS 伪造身份
        token = self.headers.get("X-Nano-Channel-Token", "")
        if token != self.channel_token:
            self._send_json(
                401,
                {
                    "error": "Unauthorized",
                    "reason": "Direct connection bypassing sandbox mediated channel is forbidden",
                },
            )
            return

        # 2. 控制面端点：启动握手锁与断连冻结监控流
        if self.path == "/__nano_control__/handshake":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "generation_id": self.engine.generation_id,
                },
            )
            return

        if self.path == "/__nano_control__/watch":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(f"alive {self.engine.generation_id}\n".encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        # 3. 提取可信进程二进制身份（优先使用 sandbox.py 观察到的身份，回退使用 SO_PEERCRED）
        bin_path = self.headers.get("X-Nano-Binary-Path")
        bin_realpath = self.headers.get("X-Nano-Binary-Realpath")
        bin_sha256 = self.headers.get("X-Nano-Binary-Sha256")
        if bin_path:
            binary = BinaryIdentity(
                path=bin_path,
                realpath=bin_realpath or bin_path,
                sha256=bin_sha256 or "",
            )
        else:
            peer_pid = get_peer_pid(self.connection)
            binary = (
                BinaryIdentity.from_pid(peer_pid)
                if peer_pid
                else BinaryIdentity("<unknown>", "<unknown>", "")
            )

        # 4. 解析目标 Host / Port / Path 并执行三层策略评估
        parsed = urllib.parse.urlsplit(self.path)
        host_hdr = self.headers.get("Host", "127.0.0.1")
        if ":" in host_hdr:
            h_name, h_port_str = host_hdr.rsplit(":", 1)
            default_port = int(h_port_str)
        else:
            h_name, default_port = host_hdr, (443 if parsed.scheme == "https" else 80)

        target_host = (parsed.hostname or h_name).lower()
        target_port = parsed.port or default_port
        target_path = parsed.path or "/"
        if parsed.query:
            target_path += f"?{parsed.query}"

        decision = self.engine.evaluate(
            method=self.command,
            url_or_path=target_path,
            host=target_host,
            port=target_port,
            binary=binary,
        )

        if not decision.allowed:
            if decision.denial_record:
                self.aggregator.record(decision.denial_record)
            self._send_json(
                403,
                {
                    "error": "Blocked by Nano-OpenShell Supervisor",
                    "stage": decision.stage,
                    "reason": decision.reason,
                    "binary": binary.realpath,
                },
            )
            return

        # 5. 策略放行：剥离内部 X-Nano-* 与客户端伪造的 Authorization 头，注入真实凭证转发至上游
        content_len = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_len) if content_len > 0 else None

        forward_headers = {
            k: v
            for k, v in self.headers.items()
            if not k.lower().startswith("x-nano-")
            and k.lower() != "host"
            and k.lower() != "authorization"
        }
        forward_headers["Host"] = f"{target_host}:{target_port}"
        forward_headers.update(decision.inject_headers)

        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.upstream_port, timeout=5)
            conn.request(self.command, target_path, body=body, headers=forward_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.getheader("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()
        except Exception as exc:
            self._send_json(502, {"error": "Upstream connection failed", "detail": str(exc)})

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle_all


def start_mock_upstream(port: int) -> socketserver.ThreadingTCPServer:
    """启动本地回显测试上游，用于验证 Supervisor 是否成功注入真实凭证"""

    class EchoUpstreamHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def _echo(self) -> None:
            payload = {
                "upstream": "mock-openai-server",
                "method": self.command,
                "path": self.path,
                "host": self.headers.get("Host"),
                "received_authorization": self.headers.get("Authorization", "<NONE>"),
            }
            raw = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_PUT = do_DELETE = _echo

    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = ReusableTCPServer(("127.0.0.1", port), EchoUpstreamHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    policy_path = os.environ.get("NANO_POLICY_PATH", os.path.join(base_dir, "policy.yaml"))
    sock_path = os.environ.get("NANO_SOCK_PATH", DEFAULT_SOCK_PATH)
    channel_token = os.environ.get("NANO_CHANNEL_TOKEN", DEFAULT_CHANNEL_TOKEN)
    upstream_port = int(os.environ.get("NANO_UPSTREAM_PORT", str(DEFAULT_UPSTREAM_PORT)))

    engine = PolicyEngine.from_yaml_file(policy_path)
    aggregator = DenialAggregator(base_dir=base_dir, baseline_policy=engine.raw)

    start_mock_upstream(upstream_port)
    if os.path.exists(sock_path):
        os.unlink(sock_path)

    SupervisorHandler.engine = engine
    SupervisorHandler.aggregator = aggregator
    SupervisorHandler.channel_token = channel_token
    SupervisorHandler.upstream_port = upstream_port

    server = ThreadingUnixHTTPServer(sock_path, SupervisorHandler)
    print(
        f"[supervisor] Ready on UDS {sock_path} | generation={engine.generation_id} "
        f"| mock_upstream=127.0.0.1:{upstream_port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


if __name__ == "__main__":
    main()
