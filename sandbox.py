#!/usr/bin/env python3
"""
Nano-OpenShell Milestone 3: Inside the Sandbox Boundary.
Linux User+Net Namespace Isolation, /proc Socket-to-Binary Observer,
Fail-Closed Handshake Lock & SIGSTOP Disconnect Freeze.
"""
from __future__ import annotations

import fcntl
import glob
import http.client
import http.server
import json
import os
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
from typing import Any, Optional

from policy import BinaryIdentity

DEFAULT_SOCK_PATH = "/tmp/nano-supervisor.sock"
DEFAULT_CHANNEL_TOKEN = "nano-mediated-token-v1"
CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
CLONE_NEWNET = getattr(os, "CLONE_NEWNET", 0x40000000)
SIOCSIFFLAGS = 0x8914
IFF_UP_RUNNING = 0x1 | 0x40  # IFF_UP (0x1) | IFF_RUNNING (0x40)


def enter_isolated_namespaces() -> None:
    """创建隔离的 User + Network + Mount Namespace 并原生活跃 lo 回环网卡"""
    orig_uid, orig_gid = os.getuid(), os.getgid()
    os.unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)

    # 1. 严格按内核要求顺序写入 setgroups -> uid_map -> gid_map
    with open("/proc/self/setgroups", "w", encoding="utf-8") as f:
        f.write("deny\n")
    with open("/proc/self/uid_map", "w", encoding="utf-8") as f:
        f.write(f"0 {orig_uid} 1\n")
    with open("/proc/self/gid_map", "w", encoding="utf-8") as f:
        f.write(f"0 {orig_gid} 1\n")

    # 2. 使用 ioctl(SIOCSIFFLAGS) 原生拉起沙箱内的 lo (127.0.0.1) 接口
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH", b"lo", IFF_UP_RUNNING)
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)
    finally:
        sock.close()


def resolve_client_binary(client_port: int) -> BinaryIdentity:
    """通过沙箱内 /proc/self/net/tcp 与 /proc/<pid>/fd 反查发起连接的真实进程二进制"""
    port_suffix = f":{client_port:04X}"
    target_inode: Optional[str] = None

    for tcp_table in ("/proc/self/net/tcp", "/proc/self/net/tcp6"):
        if not os.path.exists(tcp_table):
            continue
        try:
            with open(tcp_table, "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 10 and cols[1].upper().endswith(port_suffix):
                        target_inode = cols[9]
                        break
        except OSError:
            continue
        if target_inode and target_inode != "0":
            break

    if not target_inode or target_inode == "0":
        return BinaryIdentity("<unknown>", "<unknown>", "")

    socket_tag = f"socket:[{target_inode}]"
    self_pid = os.getpid()
    for fd_path in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            pid_str = fd_path.split("/")[2]
            pid = int(pid_str)
            if pid == self_pid:
                continue
            if os.readlink(fd_path) == socket_tag:
                return BinaryIdentity.from_pid(pid)
        except (OSError, ValueError):
            continue

    return BinaryIdentity("<unknown>", "<unknown>", "")


class UnixHTTPConnection(http.client.HTTPConnection):
    """通过 Unix Domain Socket 连接宿主机 Supervisor 的 HTTP 客户端"""

    def __init__(self, sock_path: str, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.sock_path = sock_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.sock_path)


class SandboxBrokerHandler(http.server.BaseHTTPRequestHandler):
    sock_path: str
    channel_token: str

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _bridge_to_supervisor(self) -> None:
        # 1. 在隔离边界内通过 /proc 采样真实调用进程身份（绝不在沙箱内做策略决策）
        client_port = self.client_address[1]
        bin_id = resolve_client_binary(client_port)

        content_len = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_len) if content_len > 0 else None

        headers = {
            k: v
            for k, v in self.headers.items()
            if not k.lower().startswith("x-nano-")
        }
        # 2. 注入 Mediated Channel 令牌与可信进程身份元数据
        headers["X-Nano-Channel-Token"] = self.channel_token
        headers["X-Nano-Binary-Path"] = bin_id.path
        headers["X-Nano-Binary-Realpath"] = bin_id.realpath
        headers["X-Nano-Binary-Sha256"] = bin_id.sha256

        try:
            conn = UnixHTTPConnection(self.sock_path, timeout=5.0)
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()
        except Exception as exc:
            err = (
                json.dumps({"error": "Mediated channel error", "detail": str(exc)}) + "\n"
            ).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _bridge_to_supervisor


def perform_startup_handshake(sock_path: str, channel_token: str) -> str:
    """Fail-Closed 启动锁：与 Supervisor 完成 generation_id 握手，失败则拒绝启动 Agent"""
    try:
        conn = UnixHTTPConnection(sock_path, timeout=3.0)
        conn.request(
            "GET",
            "/__nano_control__/handshake",
            headers={"X-Nano-Channel-Token": channel_token},
        )
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        if resp.status == 200 and data.get("status") == "ok":
            return data["generation_id"]
        raise RuntimeError(f"Unexpected handshake response: {resp.status} {data}")
    except Exception as exc:
        print(
            f"[sandbox][FAIL-CLOSED] Supervisor mediated handshake failed ({exc}), "
            "refusing to launch workload!",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(125)


def watch_supervisor_or_freeze(
    sock_path: str, channel_token: str, workload_proc: subprocess.Popen[bytes]
) -> None:
    """后台监控 Mediated 控制流：一旦与 Supervisor 断连，立即发送 SIGSTOP 冻结整个 Agent 进程组"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        req = (
            "GET /__nano_control__/watch HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"X-Nano-Channel-Token: {channel_token}\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(req)
        while workload_proc.poll() is None:
            chunk = sock.recv(256)
            if not chunk:
                break
    except OSError:
        pass

    if workload_proc.poll() is None:
        print(
            f"\n[sandbox][FAIL-CLOSED] Mediated channel lost! "
            f"Sending SIGSTOP to workload pgid={workload_proc.pid}",
            file=sys.stderr,
            flush=True,
        )
        try:
            os.killpg(workload_proc.pid, signal.SIGSTOP)
        except ProcessLookupError:
            pass


def build_sanitized_env(proxy_port: int) -> dict[str, str]:
    """清洗宿主机敏感环境变量，防止任何真实密钥或 Channel Token 泄露进沙箱"""
    clean_env: dict[str, str] = {}
    for k, v in os.environ.items():
        upper_k = k.upper()
        if (
            upper_k.startswith(("REAL_", "NANO_"))
            or upper_k.endswith(("_KEY", "_SECRET", "_TOKEN"))
            or upper_k in ("NO_PROXY", "HTTP_PROXY", "HTTPS_PROXY")
        ):
            continue
        clean_env[k] = v

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    clean_env["HTTP_PROXY"] = proxy_url
    clean_env["http_proxy"] = proxy_url
    clean_env["HTTPS_PROXY"] = proxy_url
    clean_env["https_proxy"] = proxy_url
    return clean_env


def main() -> None:
    cmd = sys.argv[1:]
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Usage: python3 sandbox.py -- <COMMAND> [ARGS...]", file=sys.stderr)
        sys.exit(2)

    sock_path = os.environ.get("NANO_SOCK_PATH", DEFAULT_SOCK_PATH)
    channel_token = os.environ.get("NANO_CHANNEL_TOKEN", DEFAULT_CHANNEL_TOKEN)

    # 1. 进入 Linux User + Network + Mount 隔离命名空间并激活 lo
    enter_isolated_namespaces()

    # 2. Fail-Closed 启动锁：未确认 Supervisor 在线与 generation_id 前绝不启动子进程
    gen_id = perform_startup_handshake(sock_path, channel_token)

    # 3. 启动沙箱内本地代理观察器 (127.0.0.1:<随机空闲端口>)
    SandboxBrokerHandler.sock_path = sock_path
    SandboxBrokerHandler.channel_token = channel_token

    class ThreadedLocalBroker(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    broker = ThreadedLocalBroker(("127.0.0.1", 0), SandboxBrokerHandler)
    proxy_port = broker.server_address[1]
    threading.Thread(target=broker.serve_forever, daemon=True).start()

    # 4. 擦除敏感环境变量并在独立进程组 (start_new_session=True) 中启动 Agent 工作负载
    child_env = build_sanitized_env(proxy_port)
    print(
        f"[sandbox] Boundary active (gen={gen_id}, local_broker=127.0.0.1:{proxy_port})",
        file=sys.stderr,
        flush=True,
    )
    proc = subprocess.Popen(cmd, env=child_env, start_new_session=True)

    # 5. 启动断连 SIGSTOP 看门狗线程
    threading.Thread(
        target=watch_supervisor_or_freeze,
        args=(sock_path, channel_token, proc),
        daemon=True,
    ).start()

    sys.exit(proc.wait())


if __name__ == "__main__":
    main()
