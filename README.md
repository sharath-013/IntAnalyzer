# IntAnalyze

**The code on GitHub isn't always the code you install. IntAnalyze tells you the difference.**

IntAnalyze ("Int" for *integrity*) compares a **published npm package** (e.g. `ms@2.1.3`) with
its **source repository** at the matching commit or tag, explains **every** difference, and
alerts on suspicious releases:

```
dist/index.js    EXPECTED    compiled output of src/index.ts
package.json     SUSPICIOUS  new postinstall script that is not in the source
lib/x.min.js     SUSPICIOUS  obfuscated file found nowhere in the repo
```

Built at **Hacktoberfest Hack Day Sonipat** by **TEAM MLS** for *Problem 4: Does the package
match its source?*

## Why

Supply-chain attacks hide in the artifact people install, not in the repository they review:

- **xz-utils (2024):** the backdoor was in the release tarball, not in git.
- **event-stream (2018):** a new maintainer shipped a malicious dependency in a published version.
- **ua-parser-js (2021):** hijacked releases ran crypto-miners and stole credentials on install.
- **Shai-Hulud npm worm (2025):** malicious `postinstall` scripts in published packages spread
  through stolen npm tokens.

Reading the GitHub repo doesn't protect you if the published package is different.
IntAnalyze checks exactly that gap.

## Team

TEAM MLS: Maryada Sharath Chandra Reddy, Sugunesh Dande, Adem Aravind, BBSVS Praveen.

## Install

Python 3.11+ and `git` are required.

```bash
git clone https://github.com/sharath-013/IntAnalyzer.git
cd IntAnalyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
intanalyze version
```

## Optional: local LLM explanations (LM Studio + Qwen3.5 9B)

Verdicts come from deterministic rules. The LLM only turns findings into plain-English
explanations. It is an **open-weight model running on your machine**, so no API keys are
needed and no package code leaves your computer.

1. Install [LM Studio](https://lmstudio.ai) and download **Qwen3.5 9B** (`qwen/qwen3.5-9b`).
2. Start the server and load the model:
   ```bash
   lms server start
   lms load qwen/qwen3.5-9b
   ```
3. Check that IntAnalyze can see it:
   ```bash
   intanalyze doctor
   ```

If your LM Studio server is not on the default `http://localhost:1234/v1`, set
`INTANALYZE_LLM_URL`, for example `export INTANALYZE_LLM_URL=http://localhost:1235/v1`.
`INTANALYZE_MODEL` (or `--model`) picks a different model id. Without the server, everything
still works: you get one warning and rule-based explanations.

## Usage

```bash
# Check a published package against its declared repository
intanalyze check ms@2.1.3
intanalyze check @scope/pkg@1.2.3 --format html --out report.html

# Pick the source yourself
intanalyze check some-pkg@2.0.0 --repo https://github.com/owner/repo --ref v2.0.0

# Fully offline: a local tarball against a local source tree (used by tests, CI, examples)
intanalyze check --tarball tests/fixtures/malicious/package.tgz \
                 --source tests/fixtures/malicious/source \
                 --registry-json tests/fixtures/malicious/registry.json --no-llm

intanalyze doctor     # LLM server URL, reachable?, loaded models, git/python versions
intanalyze version
```

| Option | Meaning |
|---|---|
| `--format terminal\|md\|html\|json` | Output format (default `terminal`) |
| `--out PATH` | Write the report in the chosen format to a file |
| `--no-llm` | Rule explanations only; never contact the LLM server |
| `--model NAME` | Model id on the LM Studio server (default `qwen/qwen3.5-9b`) |
| `--fail-on high\|medium\|low\|never` | Severity that makes the exit code 1 (default `high`) |
| `--repo URL`, `--ref TAG_OR_SHA` | Override the repository / ref from the registry |
| `--keep-workdir` | Keep the downloaded tarball and clone for inspection |

**Exit codes:** `0` no findings at or above `--fail-on`; `1` findings at or above it; `2` tool
error (registry, download, git or archive problem, with a message). That makes it easy to drop
into CI:

```bash
intanalyze check left-pad@1.3.0 --no-llm --fail-on medium --format json --out integrity.json
```

See [`examples/`](examples/) for real outputs: the clean fixture, the malicious fixture, and `ms@2.1.3`.

## How it works

```
  name@version
      │
      ▼
┌─────────────┐  registry.npmjs.org/<name>/<version>
│ resolve.py  │──▶ dist.tarball, dist.integrity / shasum, repository(.directory), gitHead
└─────────────┘    ref = --ref > gitHead > tag v{ver} / {ver} / {name}@{ver}
      │
      ▼
┌─────────────┐  download (HTTPS, 200 MB cap) ─▶ verify sha512/sha1 ─▶ safe_extract.py
│  fetch.py   │  git clone --depth 1 (hooks disabled, no prompts, no LFS) at the ref
└─────────────┘
      │  package/ tree            source/ tree
      ▼
┌─────────────┐  SHA-256 per file (CRLF-normalised): IDENTICAL · MODIFIED ·
│   diff.py   │  ONLY_IN_PACKAGE · ONLY_IN_SOURCE, unified diffs, binary detection
└─────────────┘
      │
      ▼
┌─────────────┐  rules/build_mapping.py  src/x.ts → dist/x.js …     ┐
│ classify.py │  rules/manifest.py       package.json field by field ├─▶ verdict + severity
└─────────────┘  rules/obfuscation.py    entropy, blobs, eval, exec… ┘    + evidence
      │
      ▼
┌─────────────┐  Qwen3.5 9B via LM Studio (local): explains CHANGED/SUSPICIOUS findings
│   llm.py    │  and writes a summary. It cannot change verdicts. Falls back to rule text.
└─────────────┘
      │
      ▼
┌─────────────┐  score: HIGH 40, MEDIUM 10, LOW 2 (cap 100) → CLEAN / REVIEW / DANGEROUS
│ score.py    │  report: terminal (Rich), Markdown, self-contained HTML, JSON
│ report.py   │
└─────────────┘
```

Each file gets a **verdict** (EXPECTED, CHANGED, SUSPICIOUS) and a **severity** (INFO, LOW,
MEDIUM, HIGH). EXPECTED files (identical, build output that maps to a source file, docs that
differ only in case or whitespace) are collapsed into counts. The risk score is the sum of the
severities of the CHANGED/SUSPICIOUS findings: **0 = CLEAN, 1–39 = REVIEW, 40+ = DANGEROUS**.

See [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) for a module-by-module explanation.

## Rules

| Rule id | Verdict / severity | What it means |
|---|---|---|
| `IA-INTEGRITY-001` | SUSPICIOUS / HIGH | Tarball hash does not match the registry's `dist.integrity` / `dist.shasum`. |
| `IA-MANIFEST-001` | SUSPICIOUS / HIGH | `preinstall` / `install` / `postinstall` added or changed versus the source `package.json` (or a `prepare` script present only in the package). |
| `IA-MANIFEST-002` | CHANGED / MEDIUM | `dependencies` / `optionalDependencies` entry that the source doesn't declare. |
| `IA-MANIFEST-003` | SUSPICIOUS / HIGH | New dependency 1–2 edits from a well-known package or an existing dependency (typosquat, e.g. `lodahs`). |
| `IA-MANIFEST-004` | SUSPICIOUS / HIGH | `main` / `bin` / `exports` points at a file that exists only in the package and is not build output. |
| `IA-MANIFEST-005` | CHANGED / LOW | Another `package.json` field differs (`version`, `gitHead`, `_*`, `devDependencies` and removed tool-config fields are ignored). |
| `IA-MANIFEST-006` | SUSPICIOUS / HIGH | Registry metadata disagrees with the tarball's `package.json` on install scripts or dependencies ("manifest confusion"). |
| `IA-CODE-001` | SUSPICIOUS / HIGH | A package-only file (or build output) contains obfuscation or dangerous APIs that its source does not. |
| `IA-CODE-002` | SUSPICIOUS / HIGH | A file present in both trees where the package version adds dangerous APIs absent from the source version. |
| `IA-FILE-001` | SUSPICIOUS / MEDIUM (CHANGED / LOW for documentation) | File found nowhere in the repository and not explained as build output. |
| `IA-FILE-002` | CHANGED / MEDIUM (LOW for documentation, or if it only removes lines) | File present in both trees with different content; the diff is in the report. |

**Obfuscation signals:** Shannon entropy > 5.2 bits/char, lines > 1000 characters (not
sourcemaps or JSON), hex/base64 blobs > 200 characters, dense `\x..` escapes,
`String.fromCharCode` chains. For build output, which is often minified, only the blob, escape
and `fromCharCode` signals apply.

**Dangerous APIs:** `eval(`, `new Function(`, `child_process`, `exec(` / `execSync(` /
`spawn(`, `require('net' | 'dgram' | 'dns')`, HTTP(S) requests to raw IP addresses,
`process.env` harvesting (tokens, keys, secrets, npm, AWS), access to `~/.npmrc` / `~/.ssh` /
`~/.aws`, and `curl` / `wget` / `powershell` inside strings. These are compared **per API
against the source**, so a library that legitimately uses `spawn` isn't flagged for it, but a
second, new `eval` is.

## Security design

- **Package code is never executed.** IntAnalyze never runs `npm install` or lifecycle
  scripts, and never imports or evaluates downloaded files. Everything is hashing, diffing and
  regexes over text.
- **Hardened extraction** (`safe_extract.py`): every tar member goes through `tarfile`'s
  `data` filter plus our own checks, which reject absolute paths, `..`, symlinks/hardlinks that
  escape the directory, device and FIFO files, archives over 200 MB and archives with more than
  20,000 members. Links are never written to disk, extracted files are `0644`, and files over
  20 MB are hashed but not analysed.
- **Safe git:** shallow clones only, with `core.hooksPath=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
  no LFS smudge, `protocol.ext` disabled, HTTPS URLs only, and refs that start with `-` refused.
  Symlinks in the source checkout are never followed.
- **Untrusted text stays inert:** HTML reports are always escaped, and the LLM prompt tells
  the model to ignore instructions found inside package content. The LLM can't change verdicts
  anyway.
- **No secrets, no cloud:** the only network calls are to the npm registry, the source git
  host, and your own local LM Studio server. The LLM client uses plain `httpx`, with no vendor
  SDK and no API key. CI uses only the built-in `GITHUB_TOKEN`.

## Limitations

- npm only, and only git sources IntAnalyze can clone over HTTPS (GitHub, GitLab, Bitbucket, …).
- Build mapping is by path convention (`src/` → `dist|lib|build|esm|cjs|out/`). Bundled
  output (one `dist/index.js` built from many files), CSS/asset pipelines and generated code
  show up as `IA-FILE-001` / `IA-FILE-002` for a human to review. IntAnalyze does not rebuild
  the package to prove the output is reproducible.
- Detection is heuristic and text-based. Determined obfuscation can evade regexes, and benign
  code can trip them, so treat the result as a review aid, not a proof.
- If neither `gitHead` nor a version tag points at the released code, pass `--ref`.
- LLM explanations can be wrong. Verdicts and evidence come from the rules, so always read
  those first.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest --cov=intanalyze            # offline; no network, no LM Studio needed
pytest -m network                  # optional live check against npm + GitHub
python tests/fixtures/build_fixtures.py   # regenerate the deterministic fixtures
scripts/make_examples.sh           # regenerate examples/ from real runs
```

The malicious test fixture is **inert**: its "payload" is unused string literals and a
documentation-range IP address (203.0.113.7). Nothing in it executes.

## AI usage

- **Product:** Qwen3.5 9B (`qwen/qwen3.5-9b`, Apache-2.0 open weights), served locally by
  LM Studio. It explains findings only.
- **Development:** the code was written with the help of Claude Code. It is not part of the
  product.

## License

[MIT](LICENSE) © 2026 TEAM MLS: Maryada Sharath Chandra Reddy, Sugunesh Dande, Adem Aravind,
BBSVS Praveen.
