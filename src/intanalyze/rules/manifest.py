"""Field-by-field comparison of the source package.json with the published one."""

from __future__ import annotations

import json
from dataclasses import dataclass

from intanalyze.models import Severity, Verdict

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
PREPARE_SCRIPTS = ("preprepare", "prepare", "postprepare")
DEP_FIELDS = ("dependencies", "optionalDependencies")
IGNORED_FIELDS = frozenset({"version", "gitHead", "devDependencies"})
# Removing other fields (tool config such as "eslintConfig", "c8", "prettier") cannot change
# what gets installed or run, so removals are only reported for these.
RUNTIME_FIELDS = frozenset(
    {"main", "module", "browser", "exports", "imports", "bin", "type", "engines", "os", "cpu",
     "peerDependencies", "bundleDependencies", "bundledDependencies", "files"}
)

# Frequently typosquatted targets; any existing dependency name is checked too.
WELL_KNOWN = frozenset(
    """
    lodash express react react-dom axios chalk commander debug request moment underscore
    async bluebird uuid yargs minimist dotenv webpack babel-core typescript jquery vue
    angular eslint prettier jest mocha chai sinon rxjs redux tslib semver glob mkdirp rimraf
    colors cross-env body-parser cookie-parser mongoose mongodb mysql pg redis socket.io
    ws node-fetch got superagent cheerio puppeteer electron next nuxt koa fastify hapi
    inquirer ora boxen yaml js-yaml xml2js jsonwebtoken bcrypt crypto-js validator
    classnames prop-types styled-components date-fns dayjs luxon ramda immutable zod
    ua-parser-js event-stream coa rc left-pad is-promise core-js regenerator-runtime
    nodemon npm yarn pnpm vite rollup esbuild sharp discord.js
    """.split()
)


@dataclass(frozen=True)
class ManifestIssue:
    rule_id: str
    severity: Severity
    verdict: Verdict
    evidence: str


def levenshtein(a: str, b: str, *, transpositions: bool = False) -> int:
    """Edit distance; with ``transpositions`` a swap of adjacent letters counts as one edit
    (optimal string alignment), which is how most typosquats are made ("axois")."""
    if a == b:
        return 0
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if transpositions and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _bare(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def typosquat_target(name: str, existing: set[str]) -> str | None:
    """Well-known or existing package that ``name`` looks like a misspelling of."""
    bare = _bare(name).lower()
    if len(bare) < 4 or bare in WELL_KNOWN:
        return None
    max_dist = 1 if len(bare) < 6 else 2
    for target in sorted(WELL_KNOWN | {_bare(e).lower() for e in existing}):
        if target != bare and abs(len(target) - len(bare)) <= max_dist:
            if levenshtein(bare, target, transpositions=True) <= max_dist:
                return target
    return None


def _entry_paths(value: object) -> list[str]:
    """All file paths referenced by main / bin / exports (nested conditions included)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [p for v in value.values() for p in _entry_paths(v)]
    if isinstance(value, list):
        return [p for v in value for p in _entry_paths(v)]
    return []


def _norm_path(p: str) -> str:
    p = p.strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def entry_points(manifest: dict) -> list[tuple[str, str]]:
    out = []
    for field in ("main", "module", "bin", "exports"):
        for p in _entry_paths(manifest.get(field)):
            out.append((field, _norm_path(p)))
    return out


def _script(m: dict, name: str) -> str | None:
    scripts = m.get("scripts")
    if isinstance(scripts, dict) and isinstance(scripts.get(name), str):
        return scripts[name]
    return None


def _deps(m: dict, field: str) -> dict[str, str]:
    deps = m.get(field)
    return {k: str(v) for k, v in deps.items()} if isinstance(deps, dict) else {}


def _canon(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def compare_manifests(
    source: dict | None,
    package: dict,
    *,
    unexplained_files: set[str] | frozenset[str] = frozenset(),
) -> list[ManifestIssue]:
    """Issues in the published package.json relative to the source one.

    ``unexplained_files`` are package-only files that are not build output; an entry
    point that lands on one of them is flagged.
    """
    source = source or {}
    issues: list[ManifestIssue] = []

    for name in INSTALL_SCRIPTS + PREPARE_SCRIPTS:
        cmd = _script(package, name)
        if cmd is None:
            continue
        before = _script(source, name)
        if name in PREPARE_SCRIPTS and before is not None:
            continue
        if before is None:
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-001",
                    Severity.HIGH,
                    Verdict.SUSPICIOUS,
                    f'scripts.{name} = "{cmd}" is not in the source package.json',
                )
            )
        elif before != cmd:
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-001",
                    Severity.HIGH,
                    Verdict.SUSPICIOUS,
                    f'scripts.{name} changed: source "{before}" -> package "{cmd}"',
                )
            )

    existing = {n for f in DEP_FIELDS + ("devDependencies", "peerDependencies")
                for n in _deps(source, f)}
    for field in DEP_FIELDS:
        src_deps, pkg_deps = _deps(source, field), _deps(package, field)
        for name, spec in sorted(pkg_deps.items()):
            if name in src_deps:
                if src_deps[name] != spec:
                    issues.append(
                        ManifestIssue(
                            "IA-MANIFEST-005",
                            Severity.LOW,
                            Verdict.CHANGED,
                            f'{field}.{name} changed: "{src_deps[name]}" -> "{spec}"',
                        )
                    )
                continue
            target = typosquat_target(name, existing - {name})
            if target:
                issues.append(
                    ManifestIssue(
                        "IA-MANIFEST-003",
                        Severity.HIGH,
                        Verdict.SUSPICIOUS,
                        f'new {field}.{name} ("{spec}") looks like a typosquat of "{target}"',
                    )
                )
            else:
                issues.append(
                    ManifestIssue(
                        "IA-MANIFEST-002",
                        Severity.MEDIUM,
                        Verdict.CHANGED,
                        f'new {field}.{name} ("{spec}") is not in the source package.json',
                    )
                )

    for field, path in entry_points(package):
        if path in unexplained_files:
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-004",
                    Severity.HIGH,
                    Verdict.SUSPICIOUS,
                    f"{field} points to {path}, which exists only in the package and is not "
                    "build output",
                )
            )

    handled = {"scripts", *DEP_FIELDS}
    for key in sorted(set(source) | set(package)):
        if key in handled or key in IGNORED_FIELDS or key.startswith("_"):
            continue
        if key not in package and key not in RUNTIME_FIELDS:
            continue
        if _canon(source.get(key)) != _canon(package.get(key)):
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-005",
                    Severity.LOW,
                    Verdict.CHANGED,
                    f"field {key!r} differs from the source package.json",
                )
            )
    return issues


def compare_registry_manifest(registry: dict | None, package: dict) -> list[ManifestIssue]:
    """Manifest confusion: the registry's metadata must describe the tarball's package.json."""
    if not registry:
        return []
    issues = []
    for name in INSTALL_SCRIPTS:
        reg, tar = _script(registry, name), _script(package, name)
        # npm itself adds this install script to the metadata of packages with binding.gyp.
        if name == "install" and tar is None and reg == "node-gyp rebuild":
            continue
        if reg != tar:
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-006",
                    Severity.HIGH,
                    Verdict.SUSPICIOUS,
                    f"scripts.{name}: registry says {reg!r} but the tarball has {tar!r}",
                )
            )
    for field in DEP_FIELDS:
        reg, tar = set(_deps(registry, field)), set(_deps(package, field))
        if field in registry and reg != tar:
            diff = sorted(reg ^ tar)
            issues.append(
                ManifestIssue(
                    "IA-MANIFEST-006",
                    Severity.HIGH,
                    Verdict.SUSPICIOUS,
                    f"{field} in registry metadata and tarball differ: {', '.join(diff)}",
                )
            )
    return issues
