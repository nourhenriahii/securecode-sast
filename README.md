# SecureCode

**A static application security scanner (SAST) for Python and JavaScript projects, with an optional AI layer that explains findings.**

SecureCode reads source code without running it and reports the kind of mistakes that lead to real breaches: secrets committed to a repository, SQL and command injection, dangerous functions, and insecure server settings. Every result has a severity, an exact file and line, a plain-language explanation and a suggested fix.

It uses only the Python standard library (no dependencies), and the detection itself is rule-based and deterministic. The AI layer is optional and never decides what is a vulnerability.

```
python3 scanner.py my_project --explain
```

## Why this project exists

I built it to understand how tools such as Bandit, Semgrep and gitleaks work from the inside, instead of only running them. The goals were:

1. Learn the techniques behind SAST: pattern matching, entropy analysis, and abstract syntax tree (AST) analysis.
2. Learn what makes static analysis hard: false positives, false negatives, and where it stops being useful.
3. Make results understandable to people who are not security specialists.
4. Use AI where it helps (explaining and triaging) without trusting it for detection.

## What it protects against

| Rule | What it detects | Why it matters | Reference | Severity |
|---|---|---|---|---|
| `hardcoded-credential` | Passwords, API keys, tokens and secrets written in code or `.env` files. An entropy filter skips placeholders such as `changeme`. | Anyone with read access to the repository can use the account. | CWE-798 | High |
| `known-token-format` | Tokens with known provider prefixes (`gsk_`, `ghp_`, `sk-`, ...) whatever the variable is called. | Catches secrets stored under unusual names. | CWE-798 | High |
| `aws-access-key` | AWS access key IDs. | Bots scan public repositories for these within minutes. | CWE-798 | High |
| `private-key` | Private key blocks committed to the project. | Allows impersonating a server or decrypting traffic. | CWE-321 | High |
| `dangerous-exec` | `eval()` and `exec()`. | Runs text as code; user input becomes code execution. | CWE-95 | High |
| `sql-injection` | Queries built with f-strings, `+`, `%` or `.format()` passed to `execute()`, including a query first stored in a variable. | Lets an attacker read or change the database. | CWE-89, OWASP A03 | High |
| `os-system` | `os.system()` and `os.popen()`; High when the command is built from a dynamic string. | Command injection. | CWE-78 | Medium / High |
| `shell-true` | `subprocess` called with `shell=True`. | Command injection through the shell. | CWE-78 | Medium |
| `unsafe-deserialization` | `pickle.load()` and `pickle.loads()`. | Loading an untrusted pickle can execute code. | CWE-502 | Medium |
| `applescript-injection` | AppleScript built from f-strings with unescaped values. Downgraded to Low (`applescript-escaped`) when every value passes through `escape()`. | A crafted value can break out of the string and run extra commands. | CWE-94 | Medium / Low |
| `debug-mode` | `run(debug=True)`. | Exposes an interactive debugger. | CWE-489 | Medium |
| `bind-all-interfaces` | The `"0.0.0.0"` address. | Makes a service reachable from the whole network. | CWE-605 | Medium |

AST-based rules run on Python files only. Secret detection runs on `.py .js .jsx .ts .tsx` and on `.env` / `.env.*` files. The folders `.git`, `venv`, `.venv`, `node_modules` and `__pycache__` are skipped.

## How it works

```
 files ──► secret detection ─────────┐
 (.py .js .jsx .ts .tsx .env*)       │   Regex + entropy filter
                                     ├──► findings ──► severity ──► masking ──► text / JSON / HTML report
 .py files ──► AST rules ────────────┘   (file, line, rule)                          │
                                                                                      └──► optional AI layer
```

- **Regex and entropy for secrets.** Secrets are text patterns, so Regex fits. Shannon entropy removes obvious placeholders (`aaaaaa`, `changeme`) to reduce false positives.
- **AST for code patterns.** Python's `ast` module parses the code into a tree, so the scanner understands structure instead of reading text. `eval` inside a comment or a string is not reported; `eval(x)` as a real call is.
- **Secrets are masked everywhere.** Reports get shared and screenshotted, so a scanner must never print the secret it found (`sk-t****`).
- **Exit code.** `0` no High findings, `1` at least one High finding, `2` usage error (for example a wrong path). This lets it fail a CI pipeline.

## Project structure

```
securecode/
├── scanner.py          Rules, CLI, and text / JSON / HTML output
├── explanations.py     Plain-language explanation and fix for every rule (English and Arabic)
├── ai_layer.py         Optional Groq layer (standard library only)
├── test_samples/       Intentionally vulnerable files used to test the rules
│   ├── vulnerable.py
│   ├── config.js
│   └── .env.example
├── tests/
│   └── test_scanner.py Regression tests
├── sample-report.html  Example of the HTML report
├── .gitignore          Keeps real secrets and generated reports out of Git
└── README.md
```

The credentials inside `test_samples/` are fake and are there on purpose.

## Installation

Requires Python 3.9 or newer (tested on 3.12 and 3.14). No `pip install` needed.

```bash
git clone https://github.com/<your-username>/securecode-sast.git
cd securecode-sast
python3 -m unittest discover -s tests -v     # optional: run the tests
```

## Usage

```bash
python3 scanner.py <path>                          # scan a file or a folder
python3 scanner.py <path> --explain                # add an explanation and a fix to each finding
python3 scanner.py <path> --format html -o report.html
python3 scanner.py <path> --format json -o report.json
python3 scanner.py <path> --lang ar --format html  # Arabic explanations
```

| Option | Meaning |
|---|---|
| `--format text\|json\|html` | Output format (default `text`) |
| `--explain` | Plain-language explanation and fix (text output) |
| `--lang en\|ar` | Language of the explanations (default `en`) |
| `-o, --output FILE` | Write the report to a file |
| `--ai` | Ask the AI to analyze each finding in its code context |
| `--ai-review` | Ask the AI for extra, unconfirmed suggestions per file |
| `--ai-max N` | Maximum findings or files sent to the AI (default 10) |
| `--model ID` | Groq model id (default `openai/gpt-oss-120b`) |

Example output:

```
[HIGH] test_samples/vulnerable.py:22  Possible SQL Injection: query built from untrusted string  (sql-injection)
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
        What it means: The SQL query is built by joining strings with user data. An attacker can change the query ...
        How to fix: Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (name,)).
```

## AI layer (optional)

The rules find the problems; the AI only explains them and suggests extra things to review.

- `--ai` sends each finding with about 15 lines of surrounding code and asks whether it is a real problem or a false positive, with a minimal fix.
- `--ai-review` asks for additional issues the rules do not cover (missing validation, path traversal, missing authentication, ...). They are listed separately as **unconfirmed** suggestions.
- AI output is labeled as a suggestion, and it never changes the exit code.

```bash
# zsh / macOS: the key stays in this terminal window only, never in code or files
read -rs "GROQ_API_KEY?Paste your Groq key: "; echo; export GROQ_API_KEY

python3 scanner.py test_samples --ai
python3 scanner.py test_samples --ai --ai-review --format html -o report.html
```

**Privacy.** Code near each finding is sent to Groq. `.env` files and private keys are never sent. Secrets are masked before sending (best effort, so do not use `--ai` on code you are not allowed to share), and only file names, not full paths, are sent. The prompt tells the model to treat the code as data, not as instructions.

**Why the AI is not the detector.** Language models can invent problems or miss real ones. Keeping detection rule-based makes results reproducible and testable. The AI is used where it is strong: explaining a finding in context and suggesting a fix.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests check that every rule fires on the sample files, that safe code is not reported (parameterized queries, placeholders, `process.env`), that secrets are masked in all outputs and before being sent to the AI, that HTML output is escaped, that tokens with unusual variable names are found, and that the AI layer stops after the first rejected API key.

## What I learned from using it

- Run on one of my own projects, it found a live API key in a `.env` file.
- Later it **missed** a key stored under the name `private-key`, because the rules looked for names such as `api_key` or `token`. That led to the `known-token-format` rule and a regression test. A scanner is only as good as its rules, and testing it on real data is how its gaps show up.
- Compared with Bandit on the same project (about 1,600 lines of Python):

| Finding | SecureCode | Bandit |
|---|---|---|
| API key in `.env` | found | missed (Python files only) |
| AppleScript built from f-strings | found; 6 of 7 downgraded after the `escape()` check | no rule |
| Server bound to `0.0.0.0` | found | found (B104) |
| `urlopen` with an unchecked scheme | not covered | found (B310) |
| Hardcoded `/tmp` path | not covered | found (B108) |
| `subprocess` called with a list (safe pattern) | not flagged | 42 low-severity notices |

Bandit reported 45 issues (0 High, 3 Medium, 42 Low); SecureCode reported 9 (1 High, 2 Medium, 6 Low) at the time. This is one project, not a benchmark. Each tool covers things the other misses, which is why teams combine several.

## Limitations

- Pattern-based: it only finds what its rules describe. **Zero findings does not mean the code is safe.**
- Variable tracking is shallow (one level, same file). It does not follow data across functions or files like Semgrep or CodeQL.
- The `escape()` check looks at the call, not at whether the escape function itself is correct. Review it.
- Design flaws, such as prompt injection in an LLM assistant or missing user confirmation before sending messages, cannot be found by static rules.
- Secret masking before sending to the AI is best effort.
- AI output can be wrong in both directions and is only a starting point.

## Responsible use

Run it only on code you own or are allowed to test. This is a learning and defensive tool; it reads code and never runs it.

## Roadmap

- [ ] SARIF output and a GitHub Actions workflow
- [ ] More rules (path traversal, unsafe `requests` options, JavaScript-specific patterns)
- [ ] Cross-function taint tracking
- [ ] An allowlist file to silence reviewed findings
