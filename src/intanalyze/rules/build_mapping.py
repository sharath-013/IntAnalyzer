"""Explain published files as compiled output of source files (src/x.ts -> dist/x.js)."""

from __future__ import annotations

OUTPUT_DIRS = ("dist", "lib", "build", "esm", "cjs", "out", "umd", "es", "bundles", "types",
               "typings")
# File names conventionally used for a bundle of the whole package (or of one folder).
BUNDLE_NAMES = frozenset({"index", "bundle", "main", "cdn", "umd", "browser", "standalone"})
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


def map_to_source(
    package_path: str,
    source_files: set[str] | frozenset[str],
    package_name: str | None = None,
) -> str | None:
    """Source file that ``package_path`` was compiled from, if any.

    ``dist/esm5/util/x.js`` is tried against ``src/esm5/util/x.*``, ``src/util/x.*`` and
    ``src/x.*`` (one or two build-flavour folders such as esm5/, types/ or cjs/ may sit under
    the output dir), each also without ``src/``, keeping any prefix before the output dir.
    A bundle named after the package or ``index`` (``dist/bundles/rxjs.umd.min.js``) maps to
    the package's entry file (``src/index.ts``).
    """
    parts = package_path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part not in OUTPUT_DIRS:
            continue
        prefix = "/".join(parts[:i])
        prefix = f"{prefix}/" if prefix else ""
        rest = parts[i + 1 :]
        for drop in range(min(len(rest), 3)):
            stem = strip_output_ext("/".join(rest[drop:]))
            if stem is None:
                break
            found = _find_source(prefix, stem, source_files, package_path)
            if found:
                return found
        bundle = _bundle_entry(parts[-1], prefix, source_files, package_name)
        if bundle:
            return bundle
    # Output written straight into the package root (date-fns: formatRFC7231.cjs,
    # dayjs: locale/af.js), compiled from src/.
    stem = strip_output_ext(package_path)
    if stem is not None:
        found = _find_source("", stem, source_files, package_path, root_output=True)
        if found:
            return found
        if len(parts) == 1:
            return _bundle_entry(parts[0], "", source_files, package_name)
        if parts[-1].split(".", 1)[0] in BUNDLE_NAMES:
            # e.g. locale/af/cdn.js bundles src/locale/af/index.ts
            folder = "/".join(parts[:-1])
            return _find_source("", f"{folder}/index", source_files, package_path,
                                root_output=True)
    return None


def _find_source(
    prefix: str, stem: str, source_files, package_path: str, *, root_output: bool = False
) -> str | None:
    bases = [f"{prefix}src/{stem}", f"{prefix}src/{stem}/index"]
    if not root_output:
        # Without an output dir, "x.js" next to "x.ts" is ambiguous, so require src/.
        bases += [f"{prefix}{stem}", f"{prefix}{stem}/index"]
    for base in bases:
        for ext in SOURCE_EXTS:
            if base + ext in source_files and base + ext != package_path:
                return base + ext
    return None


def _bundle_entry(filename: str, prefix: str, source_files, package_name: str | None):
    """Entry file for a bundle like ``rxjs.umd.min.js`` or ``index.production.cjs``."""
    if strip_output_ext(filename) is None:
        return None
    first = filename.split(".", 1)[0]
    bare = package_name.rsplit("/", 1)[-1] if package_name else None
    if first in BUNDLE_NAMES or first == bare:
        stems = ["index", first]
    elif bare and first.startswith(bare + "-"):
        # "<pkg>-<entry>" bundles, e.g. react-jsx-runtime.production.min.js -> jsx-runtime.js
        stems = [first[len(bare) + 1 :]]
    else:
        return None
    for stem in stems:
        found = _find_source(prefix, stem, source_files, prefix + filename)
        if found:
            return found
    return None
