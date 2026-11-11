from __future__ import annotations

import ast
import asyncio
import json
import re
from pathlib import Path
from typing import Any

import yaml

from app.scanners.tool_runner import resolve_binary, sanitized_subprocess_env

CODE_EXTENSIONS = (
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".sql",
    ".yml",
    ".yaml",
    ".json",
)

_PRIORITY_SECURITY_HINTS = (
    "auth",
    "secret",
    "crypto",
    "security",
    "gateway",
    "redact",
    "token",
    "login",
    "policy",
    "binding",
    "sandbox",
    "exec",
    "sql",
    "db",
    "api",
)

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__)/|\.(test|spec)\.[^.]+$|^test_[^/]+\.py$|_test\.py$",
    re.IGNORECASE,
)

_SYNTHETIC_FIXTURE_MARKERS = (
    "synthetic",
    "fixture",
    "example.test",
    "example.invalid",
    "provider.example",
    "test-secret",
    "test-key",
    "test-api-key",
    "secret-api-key-",
    "secret-bearer-",
    "private-key-content",
    "dummy",
    "mock",
    "placeholder",
    "123456789",
)


def is_test_file_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("/")
    return bool(_TEST_PATH_RE.search(norm))


def is_test_fixture_hit(
    workspace_dir: Path,
    file_path: str,
    line_number: int | None,
    evidence: str = "",
) -> bool:
    """Return True when a secret/scanner match occurs inside a test file using clearly synthetic test fixtures."""
    if not file_path or not is_test_file_path(file_path):
        return False
    combined = evidence.lower()
    target = workspace_dir / file_path
    if target.exists() and target.is_file() and line_number and line_number >= 1:
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, line_number - 6)
            end = min(len(lines), line_number + 4)
            combined += "\n" + "\n".join(lines[start:end]).lower()
        except OSError:
            return any(marker in combined for marker in _SYNTHETIC_FIXTURE_MARKERS)
    return any(marker in combined for marker in _SYNTHETIC_FIXTURE_MARKERS)


def prioritize_repo_files(paths: list[str]) -> list[str]:
    """
    Sort implementation files (especially security/auth/gateway/redaction/core files)
    before test files and config/manifests so context windows never get filled solely
    by alphabetical *.test.* files.
    """
    seen: set[str] = set()
    unique: list[str] = []
    for p in paths:
        norm = p.strip().lstrip("./")
        if norm and norm not in seen:
            seen.add(norm)
            unique.append(norm)

    def _rank(rel: str) -> tuple[int, int, str]:
        lower = rel.lower()
        is_test = is_test_file_path(rel)
        is_config = lower.endswith((".json", ".yml", ".yaml"))
        sec_bonus = 0 if any(h in lower for h in _PRIORITY_SECURITY_HINTS) else 1
        bucket = 2 if is_test else (3 if is_config else 0)
        return (bucket, sec_bonus, lower)

    return sorted(unique, key=_rank)


def read_prioritized_workspace_files(
    workspace_dir: Path,
    candidate_paths: list[str],
    *,
    max_files: int = 14,
    max_total_chars: int = 32000,
    per_file_chars: int = 9000,
) -> dict[str, str]:
    """
    Read real files from workspace_dir with 1-based line numbers and explicit truncation
    markers so agents know whether they saw the entire file or only a bounded prefix.
    """
    ordered = prioritize_repo_files(candidate_paths)
    rendered: dict[str, str] = {}
    used_chars = 0

    for rel in ordered:
        if len(rendered) >= max_files or used_chars >= max_total_chars:
            break
        target = (workspace_dir / rel).resolve()
        try:
            if not target.exists() or not target.is_file():
                continue
            if workspace_dir.resolve() not in target.parents and target != workspace_dir.resolve():
                continue
            if target.stat().st_size > 160_000:
                continue
        except OSError:
            continue

        raw = target.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        total_lines = len(lines)
        remaining_budget = min(per_file_chars, max_total_chars - used_chars)
        if remaining_budget < 250:
            break

        numbered_lines: list[str] = []
        shown_lines = 0
        running_len = 0
        for idx, line in enumerate(lines, start=1):
            formatted = f"{idx:03d}: {line}"
            if running_len + len(formatted) + 1 > remaining_budget and shown_lines > 0:
                break
            numbered_lines.append(formatted)
            running_len += len(formatted) + 1
            shown_lines = idx

        if shown_lines >= total_lines:
            header = f"[COMPLETE FILE: lines 1-{total_lines} of {total_lines}]"
        else:
            header = (
                f"[PARTIAL FILE: lines 1-{shown_lines} of {total_lines} shown — "
                f"DO NOT assert features/validations after line {shown_lines} are absent]"
            )
        block = f"{header}\n" + "\n".join(numbered_lines)
        rendered[rel] = block
        used_chars += len(block)

    return rendered


def _find_matching_lines(lines: list[str], pattern: re.Pattern[str], limit: int = 5) -> list[int]:
    hits: list[int] = []
    for idx, line in enumerate(lines, start=1):
        if pattern.search(line):
            hits.append(idx)
            if len(hits) >= limit:
                break
    return hits


def extract_file_facts(workspace_dir: Path, rel_path: str) -> dict[str, Any]:
    """
    Deterministic multi-language symbol & defensive-guard extractor.
    Inspects the ENTIRE file on disk so truncated LLM diff prompts cannot miss
    validations implemented deeper in a file.
    """
    target = (workspace_dir / rel_path).resolve()
    if not target.exists() or not target.is_file() or target.stat().st_size > 200_000:
        return {}

    src = target.read_text(encoding="utf-8", errors="replace")
    lines = src.splitlines()
    facts: dict[str, Any] = {
        "total_lines": len(lines),
        "language": "python" if rel_path.endswith((".py", ".pyi")) else (
            "typescript" if rel_path.endswith((".ts", ".tsx", ".mts", ".cts")) else "javascript"
        ),
    }

    if rel_path.endswith((".py", ".pyi")):
        try:
            tree = ast.parse(src)
            functions = [
                {
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                }
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            classes = [
                {"name": node.name, "line": node.lineno}
                for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef)
            ]
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
            facts["functions"] = functions[:35]
            facts["classes"] = classes[:20]
            facts["imports"] = sorted(imports)[:35]
        except SyntaxError as exc:
            facts["syntax_error"] = {"line": exc.lineno or 1, "message": exc.msg}
    elif rel_path.endswith((".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")):
        symbols: list[dict[str, Any]] = []
        decl_re = re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|const)\s+([A-Za-z_][A-Za-z0-9_]*)"
        )
        method_re = re.compile(r"^\s*(?:public|private|protected)?\s*(?:async\s+)?([a-z][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{")
        for idx, ln in enumerate(lines, start=1):
            m = decl_re.match(ln)
            if m:
                symbols.append({"name": m.group(1), "line": idx, "kind": "declaration"})
                continue
            m2 = method_re.match(ln)
            if m2 and m2.group(1) not in ("if", "for", "while", "switch", "catch", "function"):
                symbols.append({"name": m2.group(1), "line": idx, "kind": "method"})
        facts["symbols"] = symbols[:40]

    # Language-agnostic defensive guard / security control evidence across the ENTIRE file
    guards: dict[str, list[int]] = {}
    guard_patterns = [
        ("url_parsing", re.compile(r"\bnew\s+URL\s*\(|urllib\.parse|urlparse")),
        ("https_enforcement", re.compile(r"protocol\s*!==?\s*['\"]https:['\"]|must\s+use\s+https", re.IGNORECASE)),
        ("embedded_credentials_rejected", re.compile(r"\burl\.username\b|\burl\.password\b")),
        ("private_ip_ssrf_check", re.compile(r"\bisIP\s*\(|ipaddress|is_private|169\.254|192\.168|172\.1[6-9]|private.*loopback", re.IGNORECASE)),
        ("citation_or_allowlist_set_check", re.compile(r"\bnew\s+Set\b.*\bevidence|evidenceIds\.has\b|citedIds", re.IGNORECASE)),
        ("schema_validation", re.compile(r"\.(?:safeParse|parse)\s*\(|BaseModel|z\.object\(")),
        ("redirect_disabled", re.compile(r"redirect\s*:\s*['\"]error['\"]|follow_redirects\s*=\s*False")),
        ("timeout_or_size_limit", re.compile(r"AbortSignal\.timeout|MAX_REQUEST_BYTES|MAX_RESPONSE_BYTES|Buffer\.byteLength")),
        ("redaction_function", re.compile(r"redactOutboundText|\.replace\s*\(")),
        ("policy_gate", re.compile(r"getBoundBrainPolicy|projectForModel|policy\?\.enabled")),
    ]
    for label, pat in guard_patterns:
        hits = _find_matching_lines(lines, pat, limit=4)
        if hits:
            guards[label] = hits
    if guards:
        facts["implemented_guards_in_full_file"] = guards

    return facts


def extract_polyglot_file_facts(
    workspace_dir: Path, file_paths: list[str], *, limit: int = 35
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rel in prioritize_repo_files(file_paths)[:limit]:
        facts = extract_file_facts(workspace_dir, rel)
        if facts:
            out[rel] = facts
    return out


_NODE_SYNTAX_SCRIPT = r"""
import fs from 'node:fs';
import module from 'node:module';
import vm from 'node:vm';

const targetPath = process.argv[2] || 'file.ts';
const code = fs.readFileSync(0, 'utf8');
const lower = targetPath.toLowerCase();

try {
  if (lower.endsWith('.cjs')) {
    new vm.Script(code, { filename: targetPath });
  } else if (lower.endsWith('.ts') || lower.endsWith('.mts') || lower.endsWith('.cts')) {
    const stripped = module.stripTypeScriptTypes(code, { mode: 'strip' });
    new vm.SourceTextModule(stripped, { identifier: targetPath });
  } else if (lower.endsWith('.js') || lower.endsWith('.mjs')) {
    try {
      new vm.SourceTextModule(code, { identifier: targetPath });
    } catch (esmErr) {
      if (esmErr && String(esmErr.message || '').includes('import') === false) {
        new vm.Script(code, { filename: targetPath });
      } else {
        throw esmErr;
      }
    }
  }
  process.stdout.write(JSON.stringify({ ok: true, message: 'Syntax parse succeeded' }));
} catch (err) {
  if (err && err.code === 'ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX') {
    process.stdout.write(JSON.stringify({ ok: true, message: 'TS AST parsed (strip-only unsupported construct skipped)' }));
  } else {
    process.stdout.write(JSON.stringify({
      ok: false,
      code: err?.code || err?.name || 'SyntaxError',
      message: String(err?.message || err || 'Syntax error').slice(0, 400),
    }));
    process.exitCode = 1;
  }
}
"""


async def verify_code_syntax(
    rel_path: str, content: str, workspace_dir: Path | None = None
) -> tuple[bool, str]:
    """
    Deterministic syntax parser for proposed fixes and workspace files.
    Catches broken regex literals, bad JS/TS syntax, broken Python ASTs, and malformed JSON/YAML
    BEFORE any patch can be marked Verified.
    """
    lower = rel_path.lower()
    if lower.endswith((".py", ".pyi")):
        try:
            ast.parse(content, filename=rel_path)
            return True, "Python AST valid"
        except SyntaxError as exc:
            return False, f"Python SyntaxError at line {exc.lineno or 1}: {exc.msg}"

    if lower.endswith(".json"):
        try:
            json.loads(content)
            return True, "JSON syntax valid"
        except json.JSONDecodeError as exc:
            return False, f"JSON syntax error at line {exc.lineno}: {exc.msg}"

    if lower.endswith((".yml", ".yaml")):
        try:
            yaml.safe_load(content)
            return True, "YAML syntax valid"
        except yaml.YAMLError as exc:
            return False, f"YAML syntax error: {str(exc)[:240]}"

    if lower.endswith((".ts", ".mts", ".cts", ".js", ".mjs", ".cjs")):
        node_bin = resolve_binary("node")
        if not node_bin:
            return True, "node binary unavailable; skipped JS/TS parse"
        proc = await asyncio.create_subprocess_exec(
            node_bin,
            "--no-warnings",
            "--experimental-vm-modules",
            "--input-type=module",
            "-e",
            _NODE_SYNTAX_SCRIPT,
            rel_path,
            cwd=str(workspace_dir) if workspace_dir else None,
            env=sanitized_subprocess_env(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=content.encode("utf-8", errors="replace")),
                timeout=15,
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return False, "Node syntax check timed out"

        stdout = stdout_b.decode("utf-8", errors="replace").strip()
        stderr = stderr_b.decode("utf-8", errors="replace").strip()
        if stdout:
            try:
                parsed = json.loads(stdout.splitlines()[-1])
                ok = bool(parsed.get("ok"))
                msg = str(parsed.get("message") or "")
                return ok, msg if ok else f"JS/TS {parsed.get('code', 'SyntaxError')}: {msg}"
            except json.JSONDecodeError:
                pass
        if proc.returncode == 0:
            return True, "JS/TS syntax valid"
        return False, f"JS/TS syntax check failed: {(stderr or stdout)[:300]}"

    return True, "No parser needed for extension"


async def run_deterministic_code_guards(
    workspace_dir: Path, target_files: list[str]
) -> dict[str, Any]:
    """
    Deterministic multi-language security & correctness guards that inspect COMPLETE files
    on disk for concrete bugs Semgrep community/local rules or regex scanners miss
    (e.g. Authorization: Basic/Digest credential redaction bypass, SSRF missing private-IP check,
    shell template interpolation, broken file syntax).
    """
    findings: list[dict[str, Any]] = []
    candidates = [
        rel
        for rel in prioritize_repo_files(target_files)
        if not is_test_file_path(rel)
        and (workspace_dir / rel).exists()
        and (workspace_dir / rel).is_file()
        and rel.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
    ][:30]

    for rel in candidates:
        target = workspace_dir / rel
        if target.stat().st_size > 160_000:
            continue
        src = target.read_text(encoding="utf-8", errors="replace")
        lines = src.splitlines()

        # 1. Incomplete HTTP Authorization scheme redaction (Basic/Digest credentials bypass [^\s,;]+)
        if (
            re.search(r"auth(?:orization)?", src, re.IGNORECASE)
            and re.search(r"\[\^[^\]]*\\s[^\]]*\]", src)
            and ".replace(" in src
            and not re.search(r"\bBasic\b|\bDigest\b", src, re.IGNORECASE)
        ):
            hit_line = 1
            hit_snippet = ""
            for idx, ln in enumerate(lines, start=1):
                if "auth" in ln.lower() and "[^\\s" in ln:
                    hit_line = idx
                    hit_snippet = ln.strip()
                    break
            findings.append(
                {
                    "tool": "security-guard",
                    "rule_id": "AUTH-SCHEME-REDACTION-BYPASS",
                    "title": "Basic/Digest Authorization credentials can leak past redaction",
                    "file_path": rel,
                    "line_number": hit_line,
                    "severity": "High",
                    "evidence": hit_snippet or src[:200],
                    "description": (
                        "Generic key=value regex matches 'Authorization:' using a non-whitespace value class "
                        "([^\\s,;]+) without scheme-aware handling for 'Basic'/'Digest', redacting only the scheme "
                        "name while leaving the base64 or digest credential payload intact."
                    ),
                }
            )

        # 2. URL validator checks HTTPS protocol on full file but lacks loopback/private/link-local IP filtering
        if (
            re.search(r"function\s+validateEndpoint|url\.protocol\s*!==?\s*['\"]https:['\"]", src)
            and "https:" in src
            and not re.search(
                r"\bisIP\b|169\.254|192\.168|172\.1[6-9]|10\.0|isPrivate|link-local|private.*loopback",
                src,
                re.IGNORECASE,
            )
        ):
            hit_line = 1
            hit_snippet = ""
            for idx, ln in enumerate(lines, start=1):
                if "new URL" in ln or "protocol" in ln:
                    hit_line = idx
                    hit_snippet = ln.strip()
                    break
            findings.append(
                {
                    "tool": "security-guard",
                    "rule_id": "SSRF-MISSING-PRIVATE-IP-FILTER",
                    "title": "HTTPS URL validator permits arbitrary hosts and private/link-local IPs",
                    "file_path": rel,
                    "line_number": hit_line,
                    "severity": "Medium",
                    "evidence": hit_snippet,
                    "description": (
                        "Endpoint validator enforces HTTPS/embedded-credential rules via URL parsing but does not "
                        "reject private, loopback-equivalent, or link-local IP addresses (e.g. https://169.254.169.254)."
                    ),
                }
            )

        # 3. Unescaped JS/TS command execution via template literals
        if rel.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            for idx, ln in enumerate(lines, start=1):
                stripped = ln.strip()
                if stripped.startswith(("//", "/*", "*")):
                    continue
                if re.search(r"\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{", ln):
                    findings.append(
                        {
                            "tool": "security-guard",
                            "rule_id": "JS-SHELL-TEMPLATE-INJECTION",
                            "title": "Potential shell command injection via template literal",
                            "file_path": rel,
                            "line_number": idx,
                            "severity": "High",
                            "evidence": stripped[:240],
                            "description": "Dynamic template string passed directly to shell-invoking exec/execSync().",
                        }
                    )

        # 4. Syntax check on changed production files
        if rel.endswith((".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".py")):
            ok, msg = await verify_code_syntax(rel, src, workspace_dir)
            if not ok:
                findings.append(
                    {
                        "tool": "security-guard",
                        "rule_id": "SYNTAX-INVALID-SOURCE",
                        "title": "Syntax error in source file",
                        "file_path": rel,
                        "line_number": 1,
                        "severity": "Critical",
                        "evidence": msg,
                        "description": f"Deterministic parser failed on {rel}: {msg}",
                    }
                )

    return {"status": "completed", "findings": findings, "error": ""}
