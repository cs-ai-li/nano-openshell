#!/usr/bin/env python3
"""
Nano-OpenShell Milestone 1: Per-Binary Policy Schema & L4/Binary/L7 Policy Engine.
Maps to:
  - crates/openshell-policy-schema/src/lib.rs
  - crates/openshell-binary-identity/src/lib.rs
  - crates/openshell-supervisor-network/src/l7/path.rs & rest.rs
"""
from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import json
import os
import posixpath
import sys
import urllib.parse
from typing import Any, Optional
import yaml

UNTRUSTED_EXEC_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


@dataclasses.dataclass
class BinaryIdentity:
    """沙箱内发起网络请求的进程真实二进制身份 (对齐 openshell-binary-identity)"""
    path: str
    realpath: str
    sha256: str
    pid: Optional[int] = None

    @classmethod
    def from_pid(cls, pid: int) -> "BinaryIdentity":
        exe_link = f"/proc/{pid}/exe"
        realpath = os.path.realpath(exe_link)
        return cls.from_path(realpath, pid=pid)

    @classmethod
    def from_path(cls, path: str, pid: Optional[int] = None) -> "BinaryIdentity":
        realpath = os.path.realpath(path) if os.path.exists(path) else path
        sha256 = ""
        if os.path.isfile(realpath):
            h = hashlib.sha256()
            with open(realpath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        return cls(path=path, realpath=realpath, sha256=sha256, pid=pid)


@dataclasses.dataclass
class Decision:
    """策略评估结果与结构化拒绝情报 (对齐 DenialEvent)"""
    allowed: bool
    stage: str                      # ALLOWED | L4_HOST_PORT | BINARY_IDENTITY | L7_HTTP
    reason: str
    rule_name: Optional[str] = None
    inject_headers: dict[str, str] = dataclasses.field(default_factory=dict)
    credential_env: Optional[str] = None
    denial_record: Optional[dict[str, Any]] = None


class PolicyEngine:
    def __init__(self, policy_data: dict[str, Any]) -> None:
        self.raw = policy_data
        self.version = policy_data.get("version", 1)
        self.default_action = policy_data.get("default_action", "deny")
        self.rules: list[dict[str, Any]] = policy_data.get("network_policies", [])
        canonical = json.dumps(self.raw, sort_keys=True).encode("utf-8")
        self.generation_id = f"gen-{hashlib.sha256(canonical).hexdigest()[:12]}"

    @classmethod
    def from_yaml_file(cls, path: str) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    @staticmethod
    def _match_binary(binary: BinaryIdentity, patterns: list[Any]) -> bool:
        # 阻断位于临时可写目录 (/tmp, /var/tmp, /dev/shm) 的伪造可执行文件
        if binary.realpath.startswith(UNTRUSTED_EXEC_PREFIXES) or binary.path.startswith(
            UNTRUSTED_EXEC_PREFIXES
        ):
            return False
        if not patterns:
            return True  # 规则未配置 allowed_binaries 时默认允许非临时目录二进制
        candidates = {binary.path, binary.realpath}
        for pat in patterns:
            if isinstance(pat, str):
                if pat.startswith("sha256:"):
                    prefix = pat.removeprefix("sha256:").lower()
                    if binary.sha256 and binary.sha256.lower().startswith(prefix):
                        return True
                else:
                    pat_real = os.path.realpath(pat) if os.path.exists(pat) else pat
                    if any(
                        fnmatch.fnmatch(c, pat) or fnmatch.fnmatch(c, pat_real)
                        for c in candidates
                    ):
                        return True
            elif isinstance(pat, dict):
                p_glob = pat.get("path", "*")
                sha_prefix = pat.get("sha256", "").removeprefix("sha256:").lower()
                path_ok = any(fnmatch.fnmatch(c, p_glob) for c in candidates)
                sha_ok = (not sha_prefix) or (
                    bool(binary.sha256) and binary.sha256.lower().startswith(sha_prefix)
                )
                if path_ok and sha_ok:
                    return True
        return False

    def evaluate(
        self,
        method: str,
        url_or_path: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        binary: Optional[BinaryIdentity] = None,
        env: Optional[dict[str, str]] = None,
    ) -> Decision:
        env_map = env if env is not None else os.environ
        parsed = urllib.parse.urlsplit(url_or_path)
        req_host = (host or parsed.hostname or "").lower()
        req_port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
        # L7 Path 归一化：消除 '..' 与多余斜杠，防止路径穿越绕过 fnmatch 通配符
        raw_path = urllib.parse.unquote(parsed.path or "/")
        req_path = posixpath.normpath(raw_path)
        if not req_path.startswith("/"):
            req_path = "/" + req_path
        req_method = method.upper()
        bin_id = binary or BinaryIdentity(path="<unknown>", realpath="<unknown>", sha256="")

        # 1. L4 (Host + Port) 过滤
        l4_rules = []
        for rule in self.rules:
            host_ok = any(fnmatch.fnmatch(req_host, h.lower()) for h in rule.get("hosts", []))
            ports = rule.get("ports", [])
            port_ok = (not ports) or (req_port in ports)
            if host_ok and port_ok:
                l4_rules.append(rule)

        if not l4_rules:
            return self._deny(
                "L4_HOST_PORT",
                f"Host '{req_host}:{req_port}' not in egress allowlist",
                bin_id, req_host, req_port, req_method, req_path,
            )

        # 2. Binary Identity (进程真实二进制路径 / SHA-256) 过滤
        bin_rules = [
            r for r in l4_rules if self._match_binary(bin_id, r.get("allowed_binaries", []))
        ]
        if not bin_rules:
            return self._deny(
                "BINARY_IDENTITY",
                f"Binary '{bin_id.path}' (realpath='{bin_id.realpath}', "
                f"sha256={bin_id.sha256[:12]}...) not authorized for '{req_host}:{req_port}'",
                bin_id, req_host, req_port, req_method, req_path,
            )

        # 3. L7 (HTTP Method + Path) 过滤与凭证注入
        for rule in bin_rules:
            l7_rules = rule.get("l7_rules", [])
            l7_ok = not l7_rules
            for l7 in l7_rules:
                methods = [m.upper() for m in l7.get("methods", ["*"])]
                paths = l7.get("paths", ["*"])
                if ("*" in methods or req_method in methods) and any(
                    fnmatch.fnmatch(req_path, p) for p in paths
                ):
                    l7_ok = True
                    break

            if l7_ok:
                inject_headers: dict[str, str] = {}
                cred_env = None
                cred = rule.get("credential")
                if cred:
                    cred_env = cred.get("env_var")
                    secret_val = env_map.get(cred_env, f"<UNSET:{cred_env}>")
                    tpl = cred.get("value_template", f"${{{cred_env}}}")
                    inject_headers[cred["header"]] = tpl.replace(f"${{{cred_env}}}", secret_val)

                return Decision(
                    allowed=True,
                    stage="ALLOWED",
                    rule_name=rule.get("name"),
                    reason=f"Matched rule '{rule.get('name')}'",
                    inject_headers=inject_headers,
                    credential_env=cred_env,
                )

        return self._deny(
            "L7_HTTP",
            f"L7 request '{req_method} {req_path}' denied on '{req_host}:{req_port}'",
            bin_id, req_host, req_port, req_method, req_path,
        )

    @staticmethod
    def _deny(
        stage: str,
        reason: str,
        bin_id: BinaryIdentity,
        host: str,
        port: int,
        method: str,
        path: str,
    ) -> Decision:
        return Decision(
            allowed=False,
            stage=stage,
            reason=reason,
            denial_record={
                "binary": bin_id.realpath if bin_id.realpath != "<unknown>" else bin_id.path,
                "binary_invoked_as": bin_id.path,
                "binary_sha256": bin_id.sha256,
                "host": host,
                "port": port,
                "method": method,
                "path": path,
                "stage": stage,
                "reason": reason,
            },
        )


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[1] != "check":
        print("Usage: python3 policy.py check <METHOD> <URL> [--binary <PATH>] [--policy <YAML>]")
        sys.exit(2)

    method, url = sys.argv[2], sys.argv[3]
    binary_path = "/usr/bin/python3"
    policy_path = os.path.join(os.path.dirname(__file__) or ".", "policy.yaml")

    args = sys.argv[4:]
    while args:
        flag = args.pop(0)
        if flag == "--binary" and args:
            binary_path = args.pop(0)
        elif flag == "--policy" and args:
            policy_path = args.pop(0)

    engine = PolicyEngine.from_yaml_file(policy_path)
    bin_id = BinaryIdentity.from_path(binary_path)
    decision = engine.evaluate(method=method, url_or_path=url, binary=bin_id)

    if decision.allowed:
        inj = ", ".join(f"{k}={v}" for k, v in decision.inject_headers.items()) or "none"
        print(
            f"ALLOW [rule={decision.rule_name}, gen={engine.generation_id}] "
            f"(binary={bin_id.realpath}, sha256={bin_id.sha256[:12]}..., inject: {inj})"
        )
        sys.exit(0)
    else:
        print(f"DENY [{decision.stage}]: {decision.reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
