#!/usr/bin/env python3
"""SecureCode - Static Application Security Scanner (no AI, rules only)."""

import argparse
import ast
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
import html

from explanations import EXPLANATIONS, LABELS

SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
ENTROPY_THRESHOLD = 2.5  # below this = probably a placeholder (aaaaaa, xxxxxx...)
PLACEHOLDERS = {"changeme", "your_api_key", "your_password", "example", "placeholder"}

# File types to scan
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
SPECIAL_NAMES = {".env"}  # .env has no suffix in pathlib, so match it by name

# ---------------------------------------------------------------- Secrets (Regex)
# Matches: api_key = "..."  /  apiKey: "..."  /  const DB_PASSWORD = '...'  /  "password": "..."
CREDENTIAL_RE = re.compile(
    r"""(?P<name>[\w-]*(?:api[_-]?key|private[_-]?key|access[_-]?key|password|passwd|secret|token)[\w-]*)"""
    r"""["']?\s*[:=]\s*["'](?P<value>[^"'\s]{6,})["']""",
    re.I,
)
# For .env files: DB_PASSWORD=Xk29fjs8dh3  (no quotes)
ENV_RE = re.compile(
    r"^\s*(?P<name>[\w-]*(?:API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|PASSWORD|PASSWD|SECRET|TOKEN)[\w-]*)"
    r"\s*=\s*(?P<value>[^\s#]{6,})",
    re.I,
)
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")


def entropy(s):
    """Shannon entropy: helps tell a real secret from a placeholder."""
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def make(path, lineno, severity, rule, message, snippet=""):
    return {
        "file": str(path),
        "line": lineno,
        "severity": severity,
        "rule": rule,
        "message": message,
        "snippet": snippet,
    }


def looks_like_secret(value):
    return value.lower() not in PLACEHOLDERS and entropy(value) >= ENTROPY_THRESHOLD


def mask(value):
    """Show only the first 4 characters, e.g. gsk_****"""
    return value[:4] + "****"


TOKEN_PREFIX_RE = re.compile(
    r"\b(?:gsk_|sk-|ghp_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_\-]{12,}")


def redact(line):
    """Best-effort masking of secrets before text is sent to an AI service."""
    def mask_match(m):
        return m.group(0).replace(m.group("value"), mask(m.group("value")))
    line = CREDENTIAL_RE.sub(mask_match, line)
    line = ENV_RE.sub(mask_match, line)
    line = AWS_KEY_RE.sub(lambda m: mask(m.group(0)), line)
    line = TOKEN_PREFIX_RE.sub(lambda m: mask(m.group(0)), line)
    return line


def scan_secrets(path, source):
    is_env = path.name == ".env" or path.name.startswith(".env.")
    for lineno, line in enumerate(source.splitlines(), start=1):
        clean = line.strip()
        m = CREDENTIAL_RE.search(line)
        if not m and is_env:
            m = ENV_RE.search(line)
        flagged = False
        if m and looks_like_secret(m.group("value")):
            flagged = True
            value = m.group("value")
            yield make(path, lineno, "HIGH", "hardcoded-credential",
                       f"Hardcoded credential ({m.group('name')})",
                       clean.replace(value, mask(value)))
        # Known provider formats (gsk_, ghp_, sk-, ...) are detected whatever the variable is called
        tm = TOKEN_PREFIX_RE.search(line)
        if tm and not flagged and looks_like_secret(tm.group(0)):
            yield make(path, lineno, "HIGH", "known-token-format",
                       "Token with a known provider format",
                       clean.replace(tm.group(0), mask(tm.group(0))))
        am = AWS_KEY_RE.search(line)
        if am:
            yield make(path, lineno, "HIGH", "aws-access-key",
                       "AWS access key found",
                       clean.replace(am.group(0), mask(am.group(0))))
        if PRIVATE_KEY_RE.search(line):
            yield make(path, lineno, "HIGH", "private-key",
                       "Private key committed to source", clean)


# ---------------------------------------------------------------- AST rules (Python only)
def is_unsafe_sql(arg, unsafe_names=frozenset()):
    # f"SELECT ... {x}"
    if isinstance(arg, ast.JoinedStr):
        return True
    # "SELECT ..." + x   or   "SELECT ... %s" % x
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return True
    # "SELECT ... {}".format(x)
    if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"):
        return True
    # query = "..." + x  then  cursor.execute(query)  (simple variable tracking)
    if isinstance(arg, ast.Name) and arg.id in unsafe_names:
        return True
    return False


def collect_unsafe_names(tree):
    """Find variables that build SQL unsafely (not scope-aware)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and is_unsafe_sql(node.value):
            text = ast.unparse(node.value).upper()
            if any(k in text for k in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ")):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return names


def is_escape_call(expr):
    """True if the expression is escape(...) or module.escape(...)"""
    if not isinstance(expr, ast.Call):
        return False
    f = expr.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
    return "escape" in name.lower()


def scan_ast(path, source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    lines = source.splitlines()
    unsafe_names = collect_unsafe_names(tree)

    def snippet(n):
        return lines[n - 1].strip() if 0 < n <= len(lines) else ""

    for node in ast.walk(tree):
        # AppleScript built with an f-string (script injection)
        if isinstance(node, ast.JoinedStr):
            text = "".join(v.value for v in node.values
                           if isinstance(v, ast.Constant) and isinstance(v.value, str)).lower()
            if "tell application" in text or "tell app " in text:
                exprs = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
                if exprs and all(is_escape_call(e) for e in exprs):
                    yield make(path, node.lineno, "LOW", "applescript-escaped",
                               "AppleScript f-string uses escape(): verify the escape function is safe",
                               snippet(node.lineno))
                else:
                    yield make(path, node.lineno, "MEDIUM", "applescript-injection",
                               "AppleScript built with f-string with unescaped values (injection risk)",
                               snippet(node.lineno))

        # "0.0.0.0" anywhere: the service becomes reachable from the whole network
        if isinstance(node, ast.Constant) and node.value == "0.0.0.0":
            yield make(path, node.lineno, "MEDIUM", "bind-all-interfaces",
                       '"0.0.0.0" exposes the service to the whole network; use 127.0.0.1 unless needed',
                       snippet(node.lineno))

        if not isinstance(node, ast.Call):
            continue

        # eval() / exec()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            yield make(path, node.lineno, "HIGH", "dangerous-exec",
                       f"Use of {node.func.id}() can execute arbitrary code",
                       snippet(node.lineno))

        # shell=True
        for kw in node.keywords:
            if (kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                yield make(path, node.lineno, "MEDIUM", "shell-true",
                           "subprocess with shell=True (command injection risk)",
                           snippet(node.lineno))

        # os.system() / os.popen()
        if (isinstance(node.func, ast.Attribute) and node.func.attr in ("system", "popen")
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"):
            dynamic = node.args and is_unsafe_sql(node.args[0])
            yield make(path, node.lineno, "HIGH" if dynamic else "MEDIUM", "os-system",
                       "os.system/popen runs a shell command"
                       + (" built from a dynamic string" if dynamic else ""),
                       snippet(node.lineno))

        # Flask: app.run(debug=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if (kw.arg == "debug" and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True):
                    yield make(path, node.lineno, "MEDIUM", "debug-mode",
                               "run(debug=True) exposes the debugger; disable in production",
                               snippet(node.lineno))

        # cursor.execute(<unsafe query>)
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in ("execute", "executemany")
                and node.args and is_unsafe_sql(node.args[0], unsafe_names)):
            yield make(path, node.lineno, "HIGH", "sql-injection",
                       "Possible SQL Injection: query built from untrusted string",
                       snippet(node.lineno))

        # pickle.load / pickle.loads
        if isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if (isinstance(owner, ast.Name) and owner.id == "pickle"
                    and node.func.attr in ("load", "loads")):
                yield make(path, node.lineno, "MEDIUM", "unsafe-deserialization",
                           "pickle can execute code during deserialization",
                           snippet(node.lineno))


# ---------------------------------------------------------------- Runner
def should_scan(file):
    return file.is_file() and (
        file.suffix in EXTENSIONS
        or file.name in SPECIAL_NAMES
        or file.name.startswith(".env.")
    )


def iter_files(target):
    root = Path(target)
    files = [root] if root.is_file() else (
        f for f in root.rglob("*") if should_scan(f)
    )
    return [f for f in files if not (SKIP_DIRS & set(f.parts))]


def scan_path(target):
    findings = []
    for file in iter_files(target):
        source = file.read_text(encoding="utf-8", errors="ignore")
        findings += scan_secrets(file, source)   # all file types
        if file.suffix == ".py":
            findings += scan_ast(file, source)   # Python only
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    return findings


def explain(rule, lang, fallback):
    """(title, what, fix) from explanations.py"""
    return EXPLANATIONS.get(rule, {}).get(lang, (fallback, "", ""))


def format_ai(ai, L):
    """Lines describing the AI analysis of one finding."""
    if ai.get("verdict") == "not_sent":
        return [L["ai_not_sent"]]
    lines = [f"{L['ai_title']}: {L['verdict_' + ai.get('verdict', 'unsure')]}", ai.get("explanation", "")]
    if ai.get("fixed_code"):
        lines.append(f"{L['ai_fix']}:\n{ai['fixed_code']}")
    return [line for line in lines if line]


def print_text(findings, with_explain=False, lang="en", suggestions=None):
    L = LABELS[lang]
    for f in findings:
        print(f"[{f['severity']}] {f['file']}:{f['line']}  {f['message']}  ({f['rule']})")
        if f["snippet"]:
            print(f"        {f['snippet']}")
        if with_explain:
            _, what, fix = explain(f["rule"], lang, f["message"])
            print(f"        {L['what']}: {what}")
            print(f"        {L['fix']}: {fix}")
        if f.get("ai"):
            for line in format_ai(f["ai"], L):
                print("        " + line.replace("\n", "\n        "))
        print()
    if suggestions:
        print(f"== {L['ai_suggestions_title']} ==")
        print(f"({L['ai_suggestions_note']})\n")
        for s in suggestions:
            print(f"[{s['severity']}] {s['file']}:{s['line']}  {s['title']}")
            print(f"        {s['explanation']}\n")
    summary = Counter(f["severity"] for f in findings)
    print(f"Total findings: {len(findings)} "
          f"(HIGH: {summary['HIGH']}, MEDIUM: {summary['MEDIUM']}, LOW: {summary['LOW']})")


HTML_CSS = """
:root{--bg:#fafaf8;--card:#fff;--text:#1f2328;--muted:#656d76;--border:#d8dee4;--code:#f3f4f6;
--high:#cf222e;--medium:#bf8700;--low:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8b949e;
--border:#30363d;--code:#0d1117;--high:#ff7b72;--medium:#e3b341;--low:#79c0ff}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);
font:16px/1.6 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif}
main{max-width:860px;margin:0 auto}
h1{margin:0 0 4px}
h2{margin:32px 0 4px}
.muted{color:var(--muted)}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}
.stat{flex:1;min-width:120px;background:var(--card);border:1px solid var(--border);
border-radius:10px;padding:12px 16px}
.stat b{display:block;font-size:28px}
.card{background:var(--card);border:1px solid var(--border);border-inline-start:5px solid var(--border);
border-radius:10px;padding:14px 18px;margin:14px 0}
.card.high{border-inline-start-color:var(--high)}
.card.medium{border-inline-start-color:var(--medium)}
.card.low{border-inline-start-color:var(--low)}
.badge{display:inline-block;padding:1px 10px;border-radius:99px;font-size:13px;font-weight:600;
color:#fff;margin-inline-end:8px}
.badge.high{background:var(--high)}.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
.where{margin:6px 0;color:var(--muted);font-size:14px;overflow-x:auto}
pre{background:var(--code);border:1px solid var(--border);border-radius:8px;padding:10px;
overflow-x:auto;margin:8px 0;font-size:13px;text-align:left}
.ai{background:var(--code);border:1px dashed var(--border);border-radius:8px;padding:8px 14px;margin:10px 0}
p{margin:6px 0}
footer{margin-top:28px;color:var(--muted);font-size:14px}
"""


def ai_block_html(ai, L):
    if ai.get("verdict") == "not_sent":
        return f'<div class="ai muted">{L["ai_not_sent"]}</div>'
    parts = [f'<p><b>{L["ai_title"]}:</b> {L["verdict_" + ai.get("verdict", "unsure")]}</p>']
    if ai.get("explanation"):
        parts.append(f'<p>{html.escape(ai["explanation"])}</p>')
    if ai.get("fixed_code"):
        parts.append(f'<p><b>{L["ai_fix"]}:</b></p><pre dir="ltr">{html.escape(ai["fixed_code"])}</pre>')
    return f'<div class="ai">{"".join(parts)}</div>'


def build_html(findings, target, lang="en", suggestions=None):
    L = LABELS[lang]
    counts = Counter(f["severity"] for f in findings)
    direction = "rtl" if lang == "ar" else "ltr"
    cards = []
    for f in findings:
        title, what, fix = explain(f["rule"], lang, f["message"])
        sev = f["severity"].lower()
        code = f'<pre dir="ltr">{html.escape(f["snippet"])}</pre>' if f["snippet"] else ""
        ai = ai_block_html(f["ai"], L) if f.get("ai") else ""
        cards.append(
            f'<article class="card {sev}">'
            f'<div><span class="badge {sev}">{L[f["severity"]]}</span><strong>{html.escape(title)}</strong></div>'
            f'<div class="where" dir="ltr">{html.escape(f["file"])}:{f["line"]}</div>'
            f"{code}"
            f'<p><b>{L["what"]}:</b> {html.escape(what)}</p>'
            f'<p><b>{L["fix"]}:</b> {html.escape(fix)}</p>'
            f"{ai}"
            f"</article>"
        )
    body = "\n".join(cards) if cards else f'<p>{L["none"]}</p>'
    extra = ""
    if suggestions:
        items = "".join(
            f'<article class="card {s["severity"].lower()}">'
            f'<div><span class="badge {s["severity"].lower()}">{L[s["severity"]]}</span>'
            f'<strong>{html.escape(s["title"])}</strong></div>'
            f'<div class="where" dir="ltr">{html.escape(s["file"])}:{s["line"]}</div>'
            f'<p>{html.escape(s["explanation"])}</p></article>'
            for s in suggestions
        )
        extra = (f'<h2>{L["ai_suggestions_title"]}</h2>'
                 f'<p class="muted">{L["ai_suggestions_note"]}</p>{items}')
    stats = "".join(
        f'<div class="stat"><b>{n}</b>{label}</div>'
        for n, label in (
            (len(findings), L["total"]),
            (counts["HIGH"], L["HIGH"]),
            (counts["MEDIUM"], L["MEDIUM"]),
            (counts["LOW"], L["LOW"]),
        )
    )
    return (
        f'<!DOCTYPE html><html lang="{lang}" dir="{direction}"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{L["title"]}</title><style>{HTML_CSS}</style></head><body><main>'
        f'<h1>{L["title"]}</h1>'
        f'<div class="muted">{L["scanned"]}: <span dir="ltr">{html.escape(str(target))}</span></div>'
        f'<div class="summary">{stats}</div>'
        f'<p class="muted">{L["hint"]}</p>'
        f"{body}{extra}"
        f'<footer>{L["note"]}</footer></main></body></html>'
    )


def main():
    parser = argparse.ArgumentParser(description="SecureCode - static security scanner")
    parser.add_argument("target", nargs="?", default=".", help="file or folder to scan")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text")
    parser.add_argument("--explain", action="store_true",
                        help="add a plain-language explanation and fix to each finding (text output)")
    parser.add_argument("--lang", choices=["en", "ar"], default="en",
                        help="language of explanations (default: en)")
    parser.add_argument("--ai", action="store_true",
                        help="ask Groq to analyze each finding in its code context (needs GROQ_API_KEY)")
    parser.add_argument("--ai-review", action="store_true",
                        help="ask Groq for extra, unconfirmed suggestions per file (needs GROQ_API_KEY)")
    parser.add_argument("--ai-max", type=int, default=10,
                        help="max findings / files sent to the AI (default: 10)")
    parser.add_argument("--model", help="Groq model id (default: openai/gpt-oss-120b)")
    parser.add_argument("--output", "-o", help="write report to this file")
    args = parser.parse_args()

    if not Path(args.target).exists():
        print(f"Error: path not found: {args.target}", file=sys.stderr)
        sys.exit(2)

    findings = scan_path(args.target)

    suggestions = []
    if args.ai or args.ai_review:
        import ai_layer  # imported only when needed
        if not ai_layer.api_key_present():
            print("Error: GROQ_API_KEY is not set (see README, section 'AI layer').", file=sys.stderr)
            sys.exit(2)
        warning = ai_layer.key_warning()
        if warning:
            print(warning, file=sys.stderr)
        print("Note: code near each finding is sent to Groq. Secrets are masked and "
              ".env files are never sent.", file=sys.stderr)
        if args.ai:
            ai_layer.annotate(findings, redact, args.lang, args.model, args.ai_max)
        if args.ai_review:
            suggestions = ai_layer.review(iter_files(args.target), findings, redact,
                                          args.lang, args.model, args.ai_max)

    if args.format == "json":
        report = json.dumps({"total": len(findings), "findings": findings,
                             "ai_suggestions": suggestions}, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(report)
    elif args.format == "html":
        out = args.output or "securecode-report.html"
        Path(out).write_text(build_html(findings, args.target, args.lang, suggestions),
                             encoding="utf-8")
        print(f"HTML report written to {out}")
    else:
        print_text(findings, with_explain=args.explain, lang=args.lang, suggestions=suggestions)

    # exit code 1 if any HIGH finding (AI suggestions never count: they are unconfirmed)
    sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
