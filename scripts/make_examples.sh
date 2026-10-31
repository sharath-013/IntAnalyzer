#!/usr/bin/env bash
# Regenerate examples/ from real runs of intanalyze. Nothing in examples/ is hand-written:
# every terminal.txt / report.md / report.json is the output of the command in input.txt,
# and examples/README.md is generated from the resulting report.json files.
#
#   scripts/make_examples.sh            # uses the LLM if the LM Studio server is reachable
#   NO_LLM=1 scripts/make_examples.sh   # rule explanations only
#
# The LLM server URL comes from INTANALYZE_LLM_URL (default http://localhost:1234/v1).
set -uo pipefail

cd "$(dirname "$0")/.."
INTANALYZE="${INTANALYZE:-intanalyze}"
OUT=examples
LLM_FLAG=()
[[ -n "${NO_LLM:-}" ]] && LLM_FLAG=(--no-llm)
export COLUMNS=100   # fixed width so terminal.txt is stable

# run_example <dir> <intanalyze check args...>
run_example() {
  local dir="$OUT/$1"
  shift
  mkdir -p "$dir"
  # ${arr[@]+...} keeps an empty array safe under `set -u` in macOS's bash 3.2.
  local args=("$@" ${LLM_FLAG[@]+"${LLM_FLAG[@]}"})
  {
    echo "# Commands that produced the files in this folder (run from the repo root):"
    echo "export INTANALYZE_LLM_URL=${INTANALYZE_LLM_URL:-http://localhost:1234/v1}"
    echo "COLUMNS=100 intanalyze check ${args[*]} --format terminal > $dir/terminal.txt"
    echo "intanalyze check ${args[*]} --format md --out $dir/report.md"
    echo "intanalyze check ${args[*]} --format json --out $dir/report.json"
  } > "$dir/input.txt"

  echo "==> $dir"
  "$INTANALYZE" check "${args[@]}" --format terminal > "$dir/terminal.txt"
  echo "    terminal exit code: $?"
  "$INTANALYZE" check "${args[@]}" --format md --out "$dir/report.md"
  "$INTANALYZE" check "${args[@]}" --format json --out "$dir/report.json"
  echo "    json exit code: $?"
}

FX=tests/fixtures
run_example clean-fixture \
  --tarball "$FX/clean/package.tgz" --source "$FX/clean/source" \
  --registry-json "$FX/clean/registry.json"
run_example malicious-fixture \
  --tarball "$FX/malicious/package.tgz" --source "$FX/malicious/source" \
  --registry-json "$FX/malicious/registry.json"
run_example real-package ms@2.1.3

python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
rows = []
for d in ("clean-fixture", "malicious-fixture", "real-package"):
    r = json.loads((out / d / "report.json").read_text())
    llm = r["llm"]
    used = f"yes: `{llm['model']}` answered" if llm["used"] else f"no ({llm['reason']})"
    flagged = sum(1 for f in r["findings"] if f["verdict"] != "EXPECTED")
    rows.append(
        f"| [`{d}`]({d}/) | `{r['package']['name']}@{r['package']['version']}` "
        f"| **{r['status']}** | {r['score']} | {flagged} | {used} |"
    )

(out / "README.md").write_text(
    "# Examples\n\n"
    "Every file in these folders was produced by a real run of `intanalyze` with "
    "`scripts/make_examples.sh`; none of it is hand-written. Each folder has:\n\n"
    "- `input.txt`: the exact commands that were run\n"
    "- `terminal.txt`: the terminal report\n"
    "- `report.md`: the Markdown report\n"
    "- `report.json`: the full JSON report\n\n"
    "The LLM column is read from each `report.json` (`llm.used` and `llm.model`, the "
    "model id the LM Studio server reported in its response). The terminal, Markdown and "
    "JSON files come from three separate runs of the same command, so LLM wording can "
    "differ slightly between them; verdicts never do, because the rules decide them.\n\n"
    "| Example | Package | Status | Score | Flagged files | LLM used |\n"
    "|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
    "Regenerate with `scripts/make_examples.sh` (or `NO_LLM=1 scripts/make_examples.sh`).\n"
)
print(f"wrote {out / 'README.md'}")
PY
