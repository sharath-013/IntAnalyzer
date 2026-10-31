"""Explain published files as compiled output of source files (src/x.ts -> dist/x.js)."""

from __future__ import annotations

OUTPUT_DIRS = ("dist", "lib", "build", "esm", "cjs", "out")
SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
# Longest first so "x.d.ts.map" is not read as "x.d.ts" + ".map".
OUTPUT_EXTS = (".d.ts.map", ".js.map", ".d.mts", ".d.cts", ".d.ts", ".mjs", ".cjs", ".js")
CODE_EXTS = (".js", ".mjs", ".cjs")


def strip_output_ext(path: str) -> str | None:
    for ext in OUTPUT_EXTS:
        if path.endswith(ext) and len(path) > len(ext):
            return path[: -len(ext)]
    return None


def is_code(path: str) -> bool:
    return path.endswith(CODE_EXTS)


def map_to_source(package_path: str, source_files: set[str] | frozenset[str]) -> str | None:
    """Source file that ``package_path`` was compiled from, if any.

    ``dist/esm/util.js`` is tried against ``src/esm/util.*``, ``src/util.*``, ``esm/util.*``
    and ``util.*`` (with any prefix before the output dir kept, for nested packages).
    """
    parts = package_path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part not in OUTPUT_DIRS:
            continue
        prefix = "/".join(parts[:i])
        prefix = f"{prefix}/" if prefix else ""
        rest = parts[i + 1 :]
        # Allow one more output-style level, e.g. dist/cjs/x.js or lib/esm/x.js.
        variants = [rest]
        if len(rest) > 1 and rest[0] in OUTPUT_DIRS:
            variants.append(rest[1:])
        for variant in variants:
            stem = strip_output_ext("/".join(variant))
            if stem is None:
                continue
            for base in (f"{prefix}src/{stem}", f"{prefix}{stem}"):
                for ext in SOURCE_EXTS:
                    if base + ext in source_files and base + ext != package_path:
                        return base + ext
    return None
