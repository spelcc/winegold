#!/usr/bin/env python3
"""Portable local CI and AI autoreview runner for Git repositories."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT_MARKER = ".git"
DEFAULT_CONFIG = Path(".chicken/autoreview.json")
DEFAULT_PROMPT = Path(".chicken/reviewer-prompt.txt")


def run(args: list[str], *, cwd: Path, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def shell(command: str, *, cwd: Path, timeout: int = 1200) -> dict[str, Any]:
    started = time.time()
    shell_binary = os.environ.get("SHELL", "/bin/sh")
    result = subprocess.run(
        [shell_binary, "-lc", command],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-12000:],
        "duration_seconds": round(time.time() - started, 2),
    }


def repo_root(start: Path) -> Path:
    result = run(["git", "rev-parse", "--show-toplevel"], cwd=start, timeout=20)
    if result.returncode != 0:
        raise RuntimeError("Current directory is not inside a Git repository")
    return Path(result.stdout.strip()).resolve()


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing autoreview config: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Autoreview config must be a JSON object")
    return data


def untracked_diff(root: Path, max_file_bytes: int = 200_000) -> str:
    result = run(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root, timeout=20)
    if result.returncode != 0:
        return ""
    sections: list[str] = []
    for raw in result.stdout.split("\0"):
        if not raw:
            continue
        path = root / raw
        try:
            if not path.is_file() or path.stat().st_size > max_file_bytes:
                continue
            content = path.read_text(errors="replace")
        except OSError:
            continue
        added = "\n".join("+" + line for line in content.splitlines())
        sections.append(f"diff --git a/{raw} b/{raw}\nnew file mode 100644\n--- /dev/null\n+++ b/{raw}\n{added}")
    return "\n".join(sections)


def git_diff(root: Path, mode: str, base_branch: str) -> tuple[str, str]:
    if mode == "staged":
        args = ["git", "diff", "--cached", "--no-ext-diff", "--unified=80"]
        label = "staged changes"
    elif mode == "branch":
        args = ["git", "diff", "--no-ext-diff", "--unified=80", f"{base_branch}...HEAD"]
        label = f"branch diff against {base_branch}"
    else:
        args = ["git", "diff", "HEAD", "--no-ext-diff", "--unified=80"]
        label = "working tree changes"
    result = run(args, cwd=root, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Unable to collect Git diff")
    diff = result.stdout
    if mode == "working-tree":
        extra = untracked_diff(root)
        if extra:
            diff = diff.rstrip() + "\n" + extra
    return diff, label


def static_scan(diff: str) -> list[dict[str, str]]:
    patterns = [
        ("critical", "Potential hardcoded secret", r"^\+.*(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        ("high", "Shell execution with interpolation", r"^\+.*(?:os\.system\(|shell\s*=\s*True|execSync\([^)]*\$\{)"),
        ("high", "Dynamic eval or exec", r"^\+.*\b(?:eval|exec)\s*\("),
        ("high", "Unsafe deserialization", r"^\+.*pickle\.loads?\s*\("),
        ("high", "Potential SQL interpolation", r"^\+.*(?:execute\s*\(\s*f['\"]|query\s*\(\s*`[^`]*\$\{)"),
    ]
    findings: list[dict[str, str]] = []
    for severity, title, pattern in patterns:
        for match in re.finditer(pattern, diff, flags=re.IGNORECASE | re.MULTILINE):
            findings.append({"severity": severity, "title": title, "evidence": match.group(0)[:500]})
    return findings


def parse_json_response(text: str) -> dict[str, Any]:
    candidates = [text.strip()]
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    candidates.extend(fenced)
    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        for index, char in enumerate(candidate):
            if char != "{":
                continue
            try:
                data, _ = decoder.raw_decode(candidate[index:])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue
    raise RuntimeError("Reviewer returned no parseable JSON")


def opencode_review(root: Path, model: str, prompt: str) -> dict[str, Any]:
    binary = shutil.which("opencode")
    if not binary:
        raise RuntimeError("OpenCode is not installed or not available in PATH")
    args = [binary, "run", "--format", "json"]
    if model:
        args.extend(["--model", model])
    args.append(prompt)
    result = run(args, cwd=root, timeout=1200)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[-4000:] or "OpenCode failed")
    text_parts: list[str] = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            text_parts.append(line)
            continue
        if isinstance(event, dict):
            part = event.get("part") or event.get("content") or event.get("text")
            if isinstance(part, str):
                text_parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                text_parts.append(part["text"])
    combined = "\n".join(text_parts).strip() or result.stdout
    return parse_json_response(combined)


def build_prompt(template: str, *, root: Path, diff: str, diff_label: str, checks: list[dict[str, Any]], scan: list[dict[str, str]], max_chars: int) -> str:
    status = run(["git", "status", "--short"], cwd=root, timeout=20).stdout
    branch = run(["git", "branch", "--show-current"], cwd=root, timeout=20).stdout.strip()
    check_text = json.dumps(checks, ensure_ascii=False, indent=2)
    scan_text = json.dumps(scan, ensure_ascii=False, indent=2)
    clipped = diff[:max_chars]
    truncation = "\n[DIFF TRUNCATED]" if len(diff) > max_chars else ""
    return f"""{template.strip()}

Repository: {root.name}
Current branch: {branch or '(detached)'}
Review scope: {diff_label}
Git status:
{status or '(clean)'}

Deterministic command results:
{check_text}

Static scan results:
{scan_text}

DIFF START
{clipped}{truncation}
DIFF END
"""


def print_summary(report: dict[str, Any]) -> None:
    passed = report.get("passed") is True
    print("\nChicken local autoreview")
    print("=" * 26)
    print("PASS" if passed else "BLOCKED")
    print(report.get("summary") or "No reviewer summary")
    findings = report.get("findings") or []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        print(f"\n[{str(finding.get('severity', 'unknown')).upper()}] {finding.get('title', 'Finding')}")
        if finding.get("file"):
            print(f"  {finding['file']}")
        if finding.get("detail"):
            print(f"  {finding['detail']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic local CI and an independent AI review before opening a PR")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--prompt", default=str(DEFAULT_PROMPT))
    parser.add_argument("--mode", choices=["working-tree", "staged", "branch"])
    parser.add_argument("--skip-ai", action="store_true", help="Run local checks and static scan without calling the AI reviewer")
    args = parser.parse_args(argv)

    try:
        root = repo_root(Path.cwd())
        config_path = (root / args.config).resolve()
        prompt_path = (root / args.prompt).resolve()
        config = load_json(config_path)
        mode = args.mode or config.get("diff_mode", "working-tree")
        diff, diff_label = git_diff(root, mode, str(config.get("base_branch", "main")))
        if not diff.strip():
            print(f"No {diff_label} to review.")
            return 0

        checks = [shell(command, cwd=root) for command in config.get("commands", [])]
        optional = [shell(command, cwd=root) for command in config.get("optional_commands", [])]
        for result in optional:
            result["optional"] = True
        checks.extend(optional)
        scan = static_scan(diff)
        command_failed = any(result["returncode"] != 0 and not result.get("optional") for result in checks)

        if args.skip_ai:
            report = {
                "passed": not command_failed and not scan,
                "summary": "Deterministic local checks only; AI review was skipped.",
                "findings": scan,
                "test_gaps": [],
                "scope_concerns": [],
            }
        else:
            template = prompt_path.read_text()
            prompt = build_prompt(
                template,
                root=root,
                diff=diff,
                diff_label=diff_label,
                checks=checks,
                scan=scan,
                max_chars=int(config.get("max_diff_chars", 60000)),
            )
            report = opencode_review(root, str(config.get("model", "")), prompt)

        blocking = {str(value).lower() for value in config.get("blocking_severities", ["critical", "high"])}
        ai_blocking = any(
            isinstance(item, dict) and str(item.get("severity", "")).lower() in blocking
            for item in report.get("findings", [])
        )
        report["passed"] = bool(report.get("passed") is True and not ai_blocking and not scan and (not command_failed or not config.get("fail_on_command_error", True)))
        report["local_checks"] = checks
        report["static_scan"] = scan
        report["diff_mode"] = mode
        report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        report_path = (root / str(config.get("report_path", ".chicken/autoreview-result.json"))).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print_summary(report)
        print(f"\nReport: {report_path.relative_to(root)}")
        return 0 if report["passed"] else 1
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"autoreview error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
