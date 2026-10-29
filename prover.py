#!/usr/bin/env python3
"""
Nano-OpenShell Milestone 4: Static Policy Prover & Containment Verifier.
Zero-dependency static verifier blocking unsafe auto-approval of policy proposals.
Maps to:
  - crates/openshell-prover/src/containment.rs
  - crates/openshell-prover/src/queries.rs
  - crates/openshell-prover/src/finding.rs
  - crates/openshell-prover-cli/src/main.rs
"""
from __future__ import annotations

import dataclasses
import fnmatch
import posixpath
import sys
from typing import Any
import yaml

CLOUD_METADATA_ENDPOINTS = (
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "100.100.100.200",
)


@dataclasses.dataclass(frozen=True)
class Finding:
    """静态策略边界审计发现项 (对齐 openshell-prover::finding::Finding)"""
    severity: str       # CRITICAL | HIGH | MEDIUM
    code: str           # CLOUD_METADATA_GUARD | NEW_CREDENTIALED_REACH | UNAPPROVED_EGRESS_ENDPOINT | BINARY_PRIVILEGE_EXPANSION | L7_METHOD_PATH_WIDENING
    rule_name: str
    detail: str


def is_glob_subset(cand_pat: str, base_pat: str) -> bool:
    """
    判定候选通配符模式 cand_pat 是否为基准模式 base_pat 的子集 (cand_pat ⊆ base_pat)。
    算法：
      1. 将 cand_pat 中的 '*' 替换为多字符哨兵 '__WILD_STAR__'；
      2. 将 '?' 分别替换为 'a' 和 'b' 构造两个探测串；
      3. 当且仅当两个探测串均能被 fnmatchcase(probe, base_pat) 匹配时，cand_pat ⊆ base_pat。
    """
    if cand_pat == base_pat:
        return True
    starred = cand_pat.replace("*", "__WILD_STAR__")
    probe_a = starred.replace("?", "a")
    probe_b = starred.replace("?", "b")
    return fnmatch.fnmatchcase(probe_a, base_pat) and fnmatch.fnmatchcase(probe_b, base_pat)


def _extract_binary_pattern(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return str(entry.get("path", "*"))
    return str(entry)


def _normalize_ports(rule: dict[str, Any]) -> list[int]:
    ports = rule.get("ports", [])
    return [int(p) for p in ports] if ports else [0]  # 0 代表未限制端口 (任意端口)


def _port_covered(cand_port: int, base_ports: list[int]) -> bool:
    if 0 in base_ports:
        return True
    if cand_port == 0:
        return False
    return cand_port in base_ports


def _expand_l7_pairs(rule: dict[str, Any]) -> list[tuple[str, str]]:
    l7_rules = rule.get("l7_rules", [])
    if not l7_rules:
        return [("*", "/*")]
    pairs: list[tuple[str, str]] = []
    for item in l7_rules:
        methods = [str(m).upper() for m in item.get("methods", ["*"])]
        paths = [str(p) for p in item.get("paths", ["/*"])]
        for m in methods:
            for p in paths:
                norm_p = posixpath.normpath(p) if not p.endswith("*") else p
                if not norm_p.startswith("/"):
                    norm_p = "/" + norm_p
                pairs.append((m, norm_p))
    return pairs


class PolicyProver:
    """策略包含性与安全不变量静态验证器 (对齐 openshell-prover)"""

    def __init__(self, baseline: dict[str, Any], candidate: dict[str, Any]) -> None:
        self.baseline_rules: list[dict[str, Any]] = baseline.get("network_policies", [])
        self.candidate_rules: list[dict[str, Any]] = candidate.get("network_policies", [])

    def verify(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()

        def emit(severity: str, code: str, rule_name: str, detail: str) -> None:
            key = (code, rule_name, detail)
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(severity=severity, code=code, rule_name=rule_name, detail=detail)
                )

        for cand_rule in self.candidate_rules:
            r_name = cand_rule.get("name", "<unnamed>")
            cand_hosts = [str(h).lower() for h in cand_rule.get("hosts", [])]
            cand_ports = _normalize_ports(cand_rule)

            # 1. [CRITICAL] CLOUD_METADATA_GUARD: 拦截云厂商元数据与链路本地地址 (含通配符双向检测)
            for host_pat in cand_hosts:
                for meta_ep in CLOUD_METADATA_ENDPOINTS:
                    if fnmatch.fnmatchcase(meta_ep, host_pat) or fnmatch.fnmatchcase(
                        host_pat, meta_ep
                    ):
                        emit(
                            "CRITICAL",
                            "CLOUD_METADATA_GUARD",
                            r_name,
                            f"Host pattern '{host_pat}' exposes cloud metadata endpoint '{meta_ep}'",
                        )

            # 2. [CRITICAL] NEW_CREDENTIALED_REACH: 拦截凭证向未授权新 (host, port) 外发
            cred = cand_rule.get("credential") or {}
            cred_env = cred.get("env_var")
            if cred_env:
                same_cred_base_rules = [
                    br
                    for br in self.baseline_rules
                    if (br.get("credential") or {}).get("env_var") == cred_env
                ]
                for c_host in cand_hosts:
                    for c_port in cand_ports:
                        covered = any(
                            any(
                                is_glob_subset(c_host, str(b_host).lower())
                                for b_host in br.get("hosts", [])
                            )
                            and _port_covered(c_port, _normalize_ports(br))
                            for br in same_cred_base_rules
                        )
                        if not covered:
                            port_disp = "*" if c_port == 0 else str(c_port)
                            emit(
                                "CRITICAL",
                                "NEW_CREDENTIALED_REACH",
                                r_name,
                                f"Credential '{cred_env}' extended to unapproved endpoint '{c_host}:{port_disp}'",
                            )

            # 查找在 L4 上覆盖当前候选规则 (host, port) 的基准规则
            for c_host in cand_hosts:
                for c_port in cand_ports:
                    covering_base = [
                        br
                        for br in self.baseline_rules
                        if any(
                            is_glob_subset(c_host, str(b_host).lower())
                            for b_host in br.get("hosts", [])
                        )
                        and _port_covered(c_port, _normalize_ports(br))
                    ]
                    port_disp = "*" if c_port == 0 else str(c_port)
                    if not covering_base:
                        emit(
                            "HIGH",
                            "UNAPPROVED_EGRESS_ENDPOINT",
                            r_name,
                            f"Endpoint '{c_host}:{port_disp}' is not covered by any baseline L4 rule",
                        )
                        continue

                    # 3. [HIGH] BINARY_PRIVILEGE_EXPANSION: 同一 (host, port) 下允许的二进制集合扩权
                    cand_bins = [
                        _extract_binary_pattern(b)
                        for b in cand_rule.get("allowed_binaries", [])
                    ]
                    if not cand_bins:
                        # 候选规则 allowed_binaries 为空代表允许 '*'
                        if not any(
                            len(br.get("allowed_binaries", [])) == 0 for br in covering_base
                        ):
                            emit(
                                "HIGH",
                                "BINARY_PRIVILEGE_EXPANSION",
                                r_name,
                                f"Rule allows unrestricted binaries ('*') on '{c_host}:{port_disp}' where baseline restricts binaries",
                            )
                    else:
                        for c_bin in cand_bins:
                            bin_ok = any(
                                len(br.get("allowed_binaries", [])) == 0
                                or any(
                                    is_glob_subset(c_bin, _extract_binary_pattern(b_bin))
                                    for b_bin in br.get("allowed_binaries", [])
                                )
                                for br in covering_base
                            )
                            if not bin_ok:
                                emit(
                                    "HIGH",
                                    "BINARY_PRIVILEGE_EXPANSION",
                                    r_name,
                                    f"Binary '{c_bin}' is not contained in baseline allowed_binaries for '{c_host}:{port_disp}'",
                                )

                    # 4. [MEDIUM] L7_METHOD_PATH_WIDENING: 同一 (host, port) 下 HTTP Method/Path 放宽
                    cand_l7_pairs = _expand_l7_pairs(cand_rule)
                    for c_method, c_path in cand_l7_pairs:
                        l7_ok = False
                        for br in covering_base:
                            for b_method, b_path in _expand_l7_pairs(br):
                                if is_glob_subset(c_method, b_method) and is_glob_subset(
                                    c_path, b_path
                                ):
                                    l7_ok = True
                                    break
                            if l7_ok:
                                break
                        if not l7_ok:
                            emit(
                                "MEDIUM",
                                "L7_METHOD_PATH_WIDENING",
                                r_name,
                                f"L7 capability '{c_method} {c_path}' widens baseline L7 rules on '{c_host}:{port_disp}'",
                            )

        return findings


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def main() -> None:
    if len(sys.argv) != 3:
        print(
            "Usage: python3 prover.py <BASELINE_POLICY.yaml> <CANDIDATE_POLICY.yaml>",
            file=sys.stderr,
        )
        sys.exit(2)

    base_path, cand_path = sys.argv[1], sys.argv[2]
    baseline = load_yaml(base_path)
    candidate = load_yaml(cand_path)

    prover = PolicyProver(baseline=baseline, candidate=candidate)
    findings = prover.verify()

    if not findings:
        print(
            f"PASS: Candidate policy '{cand_path}' is strictly contained within baseline '{base_path}' (0 findings). Auto-approval PERMITTED."
        )
        sys.exit(0)

    print(
        f"FAIL: Candidate policy '{cand_path}' violates safety/containment boundaries ({len(findings)} finding(s)). Auto-approval BLOCKED:"
    )
    for idx, f in enumerate(findings, 1):
        print(f"  {idx}. FAIL [{f.severity}] {f.code} (rule={f.rule_name}): {f.detail}")
    sys.exit(1)


if __name__ == "__main__":
    main()
