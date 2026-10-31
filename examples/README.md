# Examples

Every file in these folders was produced by a real run of `intanalyze` with `scripts/make_examples.sh`; none of it is hand-written. Each folder has:

- `input.txt`: the exact commands that were run
- `terminal.txt`: the terminal report
- `report.md`: the Markdown report
- `report.json`: the full JSON report

The LLM column is read from each `report.json` (`llm.used` and `llm.model`, the model id the LM Studio server reported in its response). The terminal, Markdown and JSON files come from three separate runs of the same command, so LLM wording can differ slightly between them; verdicts never do, because the rules decide them.

| Example | Package | Status | Score | Flagged files | LLM used |
|---|---|---|---|---|---|
| [`clean-fixture`](clean-fixture/) | `tiny-percent@1.0.0` | **CLEAN** | 0 | 0 | yes: `qwen/qwen3.5-9b` answered |
| [`malicious-fixture`](malicious-fixture/) | `tiny-percent@1.0.0` | **DANGEROUS** | 100 | 3 | yes: `qwen/qwen3.5-9b` answered |
| [`real-package`](real-package/) | `ms@2.1.3` | **CLEAN** | 0 | 0 | yes: `qwen/qwen3.5-9b` answered |

Regenerate with `scripts/make_examples.sh` (or `NO_LLM=1 scripts/make_examples.sh`).
