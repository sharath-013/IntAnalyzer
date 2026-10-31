"""Static text heuristics for obfuscated code and dangerous APIs.

This only reads text with regexes; it never parses, imports or runs the code.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

ENTROPY_THRESHOLD = 5.2
ENTROPY_MIN_CHARS = 512
LONG_LINE = 1000
BLOB_LEN = 200
HEX_ESCAPE_MIN = 24
HEX_ESCAPE_DENSITY = 0.02
FROMCHARCODE_MIN_ARGS = 8


@dataclass(frozen=True)
class Signal:
    kind: str  # "obfuscation" or "dangerous"
    name: str  # stable key, e.g. "eval" or "long-line"
    line: int | None
    detail: str

    def evidence(self) -> str:
        where = f"line {self.line}: " if self.line else ""
        return f"{where}{self.detail}"


# name -> (pattern, human description); evaluated per line.
_DANGEROUS: dict[str, tuple[re.Pattern[str], str]] = {
    "eval": (re.compile(r"\beval\s*\("), "eval() call"),
    "new-function": (re.compile(r"\bnew\s+Function\s*\("), "new Function() constructor"),
    "child_process": (re.compile(r"child_process"), "child_process module"),
    "exec": (
        re.compile(r"(?<![\w.$])exec\s*\(|\bexecSync\s*\(|\bexecFile(?:Sync)?\s*\("),
        "process execution (exec/execSync/execFile)",
    ),
    "spawn": (re.compile(r"\bspawn(?:Sync)?\s*\("), "process spawn"),
    "raw-socket": (
        re.compile(
            r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"](?:node:)?(?:net|dgram|dns)['"]"""
        ),
        "raw network module (net/dgram/dns)",
    ),
    "raw-ip-request": (
        re.compile(
            r"https?://(?!127\.|0\.0\.0\.0)\d{1,3}(?:\.\d{1,3}){3}"
            r"|(?:fetch|request|connect|get)\s*\([^)]*['\"](?!127\.|0\.0\.0\.0)\d{1,3}(?:\.\d{1,3}){3}"
        ),
        "network request to a raw IP address",
    ),
    "env-harvest": (
        re.compile(
            r"process\.env\b[^\n]{0,80}?(?:token|secret|key|passw|npm|aws|github)"
            r"|(?:JSON\.stringify|Object\.(?:keys|entries|values))\s*\(\s*process\.env\s*\)"
            r"|\.\.\.\s*process\.env\b",
            re.IGNORECASE,
        ),
        "process.env harvesting (tokens/keys/secrets)",
    ),
    "credential-files": (
        re.compile(r"\.npmrc|\.ssh[/\\\\]|\.aws[/\\\\]|id_rsa|\.git-credentials"),
        "access to credential files (~/.npmrc, ~/.ssh, ~/.aws)",
    ),
    "shell-download": (
        re.compile(
            r"""['"`][^'"`\n]*\b(?:curl|wget|powershell|Invoke-WebRequest|iwr)\b""",
            re.IGNORECASE,
        ),
        "curl/wget/powershell command in a string",
    ),
}

_HEX_BLOB = re.compile(rf"[0-9a-fA-F]{{{BLOB_LEN},}}")
_B64_BLOB = re.compile(rf"[A-Za-z0-9+/]{{{BLOB_LEN},}}={{0,2}}")
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u00[0-9a-fA-F]{2}")
_FROMCHARCODE = re.compile(r"String\.fromCharCode\s*\(([^)]*)\)")
_SOURCEMAP_LINE = re.compile(r"^\s*//[#@]\s*sourceMappingURL=")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def dangerous_signals(text: str) -> list[Signal]:
    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, (pattern, desc) in _DANGEROUS.items():
            if m := pattern.search(line):
                snippet = m.group(0)[:60]
                out.append(Signal("dangerous", name, lineno, f"{desc}: `{snippet}`"))
    return out


def dangerous_counts(text: str | None) -> Counter[str]:
    return Counter(s.name for s in dangerous_signals(text or ""))


def obfuscation_signals(text: str, *, path: str = "", minified_ok: bool = False) -> list[Signal]:
    """Obfuscation heuristics. ``minified_ok`` skips entropy and long-line checks, which
    ordinary minified build output trips."""
    out: list[Signal] = []
    data_file = path.endswith((".json", ".map"))
    lines = text.splitlines()

    if not minified_ok and not data_file and len(text) >= ENTROPY_MIN_CHARS:
        ent = shannon_entropy(text)
        if ent > ENTROPY_THRESHOLD:
            out.append(
                Signal("obfuscation", "entropy", None, f"high Shannon entropy {ent:.2f} bits/char")
            )

    for lineno, line in enumerate(lines, start=1):
        if (
            not minified_ok
            and not data_file
            and len(line) > LONG_LINE
            and not _SOURCEMAP_LINE.match(line)
        ):
            out.append(
                Signal("obfuscation", "long-line", lineno, f"{len(line)}-character line")
            )
        if _SOURCEMAP_LINE.match(line):
            continue
        if m := _HEX_BLOB.search(line):
            out.append(
                Signal("obfuscation", "hex-blob", lineno, f"{len(m.group(0))}-char hex blob")
            )
        elif not data_file and (m := _B64_BLOB.search(line)):
            out.append(
                Signal("obfuscation", "base64-blob", lineno, f"{len(m.group(0))}-char base64 blob")
            )
        for m in _FROMCHARCODE.finditer(line):
            if m.group(1).count(",") + 1 >= FROMCHARCODE_MIN_ARGS:
                out.append(
                    Signal("obfuscation", "fromcharcode", lineno, "String.fromCharCode chain")
                )
                break

    escapes = _HEX_ESCAPE.findall(text)
    density = len(escapes) * 4 / max(len(text), 1)
    if len(escapes) >= HEX_ESCAPE_MIN and density >= HEX_ESCAPE_DENSITY:
        out.append(
            Signal("obfuscation", "hex-escapes", None, f"{len(escapes)} \\x.. string escapes")
        )
    return out


def scan(text: str, *, path: str = "", minified_ok: bool = False) -> list[Signal]:
    return obfuscation_signals(text, path=path, minified_ok=minified_ok) + dangerous_signals(text)


def new_dangerous_signals(package_text: str, source_text: str | None) -> list[Signal]:
    """Dangerous-API signals in the package text that the source text does not account for.

    Compared per API by count, so a second eval() is caught even if the source has one.
    """
    allowed = dangerous_counts(source_text)
    seen: Counter[str] = Counter()
    out = []
    for sig in dangerous_signals(package_text):
        seen[sig.name] += 1
        if seen[sig.name] > allowed[sig.name]:
            out.append(sig)
    return out
