# Hackathon Submission Details

**Event:** Hacktoberfest Hack Day Sonipat (12-hour overnight hackathon)

## Project
**IntAnalyze**: "Int" stands for integrity. IntAnalyze checks whether a published
npm package matches the source code it claims to be built from.

- Python package: `intanalyze`, CLI command: `intanalyze`
- Repository: https://github.com/sharath-013/IntAnalyzer
- License: MIT

## Team Information
**Team Name:** TEAM MLS

| Role | Member | Program |
|------|--------|---------|
| Team Lead | Maryada Sharath Chandra Reddy | Computer Science & AI/ML, Rishihood University |
| Member | Sugunesh Dande | Computer Science & AI/ML, Rishihood University |
| Member | Adem Aravind | Computer Science & AI/ML, Rishihood University |
| Member | BBSVS Praveen | Computer Science & AI/ML, Rishihood University |

## Selected Problem Statement
**Problem 4: Does the package match its source?**
(Category: Software Supply Chain Security | Package Management | Security Automation)

The code on GitHub isn't always the code people install. Supply-chain attacks hide in
the published artifact rather than the repository: the xz-utils backdoor (2024) lived in
the release tarball but not in git, and event-stream (2018), ua-parser-js (2021) and the
Shai-Hulud npm worm (2025) shipped malicious code and install scripts through the
registry. IntAnalyze compares a published npm package (e.g. `ms@2.1.3`) with its source
at the matching git tag or commit, explains every difference, and flags suspicious
releases. For example:

- `dist/index.js` → EXPECTED (compiled output of `src/index.ts`)
- `package.json` → SUSPICIOUS (a new `postinstall` script that isn't in the source)
- `lib/x.min.js` → SUSPICIOUS (an obfuscated file that appears nowhere in the repo)

## AI Models Used by the Product & Justification
**Qwen3.5 9B** (`qwen/qwen3.5-9b`, Apache-2.0 open weights), served locally by LM Studio's
OpenAI-compatible server (`http://localhost:1234/v1`).

- **Why this model:** it understands code well and is small enough to run on a laptop.
  Because it runs locally, there are no API keys, and no package code ever leaves the
  machine.
- **Role:** it only *explains* differences in plain English and writes the release
  summary. It never decides verdicts or severities; a deterministic rule engine does.
- **Without the model:** the tool works fully without it (`--no-llm`, or an automatic
  fallback when the LM Studio server can't be reached).
- This is the only model the product calls. No closed or cloud APIs are used.

## AI Coding Assistant
**Claude Code** was used to help write the code. It is a development tool only and is not
part of the product.

## Planned Approach
1. **Resolve:** read npm registry metadata to get the tarball URL, integrity hash,
   repository URL, `repository.directory` and `gitHead`.
2. **Fetch:** download the tarball, verify its sha512/sha1 integrity, and extract it with
   hardened tar handling (no path traversal, no escaping links, size limits). Shallow-clone
   the source at `gitHead` or the version tag with git hooks disabled.
3. **Diff:** hash every file and label it IDENTICAL, MODIFIED, ONLY_IN_PACKAGE or
   ONLY_IN_SOURCE, with text diffs for modified files.
4. **Classify:** rules give each file a verdict (EXPECTED / CHANGED / SUSPICIOUS) and a
   severity. They cover build-output mapping (`src/` → `dist/`), `package.json` comparison
   (lifecycle scripts, new or typosquatted dependencies, entry points) and
   obfuscation/dangerous-API detection.
5. **Explain:** the local Qwen3.5 9B explains each CHANGED or SUSPICIOUS finding.
6. **Report:** a 0–100 risk score and an overall status (CLEAN / REVIEW / DANGEROUS),
   rendered as a terminal, Markdown, HTML or JSON report. The exit codes make it usable
   in CI.

**Security:** IntAnalyze never executes package code. It never runs `npm install` or
lifecycle scripts, and never imports or evaluates downloaded files.
