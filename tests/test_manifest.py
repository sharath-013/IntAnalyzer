import pytest

from intanalyze.models import Severity, Verdict
from intanalyze.rules.manifest import (
    compare_manifests,
    compare_registry_manifest,
    entry_points,
    levenshtein,
    typosquat_target,
)

SOURCE = {
    "name": "pkg",
    "version": "1.0.0",
    "main": "dist/index.js",
    "scripts": {"build": "tsc", "prepare": "tsc"},
    "dependencies": {"chalk": "^5.0.0"},
    "devDependencies": {"typescript": "^5"},
    "eslintConfig": {"root": True},
}


def _rules(issues):
    return sorted(i.rule_id for i in issues)


def test_identical_manifests_have_no_issues():
    assert compare_manifests(SOURCE, dict(SOURCE)) == []


def test_ignores_version_githead_underscore_fields_and_key_order():
    pkg = {k: SOURCE[k] for k in reversed(list(SOURCE))}
    pkg.update(version="9.9.9", gitHead="abc", _id="pkg@9.9.9", _resolved="x")
    assert compare_manifests(SOURCE, pkg) == []


def test_removed_tool_config_and_dev_deps_are_ignored():
    pkg = {k: v for k, v in SOURCE.items() if k not in ("eslintConfig", "devDependencies")}
    assert compare_manifests(SOURCE, pkg) == []


@pytest.mark.parametrize("script", ["preinstall", "install", "postinstall"])
def test_new_install_script_is_high(script):
    pkg = {**SOURCE, "scripts": {**SOURCE["scripts"], script: "node x.js"}}
    (issue,) = compare_manifests(SOURCE, pkg)
    assert issue.rule_id == "IA-MANIFEST-001"
    assert issue.severity is Severity.HIGH and issue.verdict is Verdict.SUSPICIOUS
    assert "node x.js" in issue.evidence


def test_changed_install_script_is_high():
    src = {**SOURCE, "scripts": {"postinstall": "node ok.js"}}
    pkg = {**SOURCE, "scripts": {"postinstall": "node evil.js"}}
    (issue,) = compare_manifests(src, pkg)
    assert "changed" in issue.evidence and issue.rule_id == "IA-MANIFEST-001"


def test_prepare_only_flagged_when_package_only():
    assert compare_manifests(SOURCE, dict(SOURCE)) == []
    src = {**SOURCE, "scripts": {"build": "tsc"}}
    assert _rules(compare_manifests(src, SOURCE)) == ["IA-MANIFEST-001"]


def test_new_dependency_is_medium():
    pkg = {**SOURCE, "dependencies": {**SOURCE["dependencies"], "left-pad-utils": "1"}}
    (issue,) = compare_manifests(SOURCE, pkg)
    assert issue.rule_id == "IA-MANIFEST-002" and issue.severity is Severity.MEDIUM


@pytest.mark.parametrize("name", ["lodahs", "expresss", "chalks", "@evil/axois"])
def test_typosquat_dependency_is_high(name):
    pkg = {**SOURCE, "optionalDependencies": {name: "1.0.0"}}
    (issue,) = compare_manifests(SOURCE, pkg)
    assert issue.rule_id == "IA-MANIFEST-003" and issue.severity is Severity.HIGH


def test_changed_dependency_range_is_low():
    pkg = {**SOURCE, "dependencies": {"chalk": "^5.3.0"}}
    (issue,) = compare_manifests(SOURCE, pkg)
    assert issue.rule_id == "IA-MANIFEST-005" and issue.severity is Severity.LOW


def test_entry_point_to_unexplained_file():
    pkg = {**SOURCE, "bin": {"pkg": "./lib/evil.js"}, "exports": {".": {"require": "./x.js"}}}
    issues = compare_manifests(SOURCE, pkg, unexplained_files={"lib/evil.js", "x.js"})
    assert _rules(issues).count("IA-MANIFEST-004") == 2


def test_entry_points_walks_nested_exports():
    m = {"main": "a.js", "bin": "b.js", "exports": {".": {"import": "./c.mjs"}, "./d": ["./d.js"]}}
    assert sorted(p for _, p in entry_points(m)) == ["a.js", "b.js", "c.mjs", "d.js"]


def test_other_changed_field_is_low():
    (issue,) = compare_manifests(SOURCE, {**SOURCE, "main": "lib/index.js"})
    assert issue.rule_id == "IA-MANIFEST-005"


def test_manifest_without_source():
    assert "IA-MANIFEST-002" in _rules(compare_manifests(None, {"dependencies": {"zzz-q": "1"}}))


def test_levenshtein_and_typosquat_guards():
    assert levenshtein("lodahs", "lodash") == 2
    assert levenshtein("lodahs", "lodash", transpositions=True) == 1
    assert levenshtein("", "abc") == 3
    assert typosquat_target("lodash", set()) is None  # the real thing
    assert typosquat_target("qs", set()) is None  # too short to judge
    assert typosquat_target("my-internal-lib", {"my-internal-libs"}) == "my-internal-libs"


def test_registry_manifest_confusion():
    tar = {"scripts": {}, "dependencies": {"a": "1"}}
    reg = {"scripts": {"postinstall": "node x"}, "dependencies": {"a": "1", "b": "1"}}
    assert _rules(compare_registry_manifest(reg, tar)) == ["IA-MANIFEST-006", "IA-MANIFEST-006"]
    assert compare_registry_manifest(None, tar) == []
    assert compare_registry_manifest({"scripts": {"install": "node-gyp rebuild"}}, {}) == []
