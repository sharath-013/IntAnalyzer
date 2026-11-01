"""Rule engine on the committed fixtures and on hand-built trees."""

from pathlib import Path

import pytest

from intanalyze.classify import classify
from intanalyze.diff import compare_trees
from intanalyze.models import Severity, Status, Verdict
from intanalyze.pipeline import check_offline

FIXTURES = Path(__file__).parent / "fixtures"


def _offline(name):
    d = FIXTURES / name
    return check_offline(d / "package.tgz", d / "source", registry_json=d / "registry.json")


def test_classify_clean():
    report = _offline("clean")
    assert [f for f in report.findings if f.verdict is not Verdict.EXPECTED] == []
    assert report.status is Status.CLEAN and report.score == 0
    assert report.integrity.ok is True
    assert report.expected_counts == {
        "build_output": 4, "identical": 2, "manifest": 1, "only_in_source": 4,
    }
    mapped = {f.path: f.mapped_source for f in report.findings if f.mapped_source}
    assert mapped["dist/index.js"] == "src/index.ts"
    assert mapped["dist/util.d.ts"] == "src/util.ts"


def test_classify_malicious():
    report = _offline("malicious")
    by_path = {f.path: f for f in report.findings}
    assert report.status is Status.DANGEROUS and report.score == 100

    manifest = by_path["package.json"]  # (a) postinstall and (d) typosquat
    assert manifest.verdict is Verdict.SUSPICIOUS and manifest.severity is Severity.HIGH
    assert manifest.rule_ids == ["IA-MANIFEST-001", "IA-MANIFEST-003"]
    assert any('postinstall = "node lib/x.min.js"' in e for e in manifest.evidence)
    assert any("lodahs" in e and "lodash" in e for e in manifest.evidence)

    payload = by_path["lib/x.min.js"]  # (b) obfuscated file found nowhere in the repo
    assert payload.rule_ids == ["IA-CODE-001"] and payload.severity is Severity.HIGH
    assert any("child_process" in e for e in payload.evidence)
    assert any("203.0.113.7" in e for e in payload.evidence)

    dist = by_path["dist/index.js"]  # (c) eval( added to the build output
    assert dist.rule_ids == ["IA-CODE-001"] and dist.mapped_source == "src/index.ts"
    assert any(e.startswith("line 12: eval()") for e in dist.evidence)

    suspicious = {f.path for f in report.findings if f.verdict is Verdict.SUSPICIOUS}
    assert suspicious == {"package.json", "lib/x.min.js", "dist/index.js"}


def test_every_finding_has_a_rule_explanation():
    for f in _offline("malicious").findings:
        assert f.explanation is not None and f.explanation_source == "rules"


def _tree(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _run(tmp_path, pkg_files, src_files, registry=None):
    pkg, src = tmp_path / "pkg", tmp_path / "src"
    _tree(pkg, pkg_files)
    _tree(src, src_files)
    result = classify(compare_trees(pkg, src), pkg, src, registry_manifest=registry)
    return {f.path: f for f in result.findings}, result.expected_counts


def test_modified_file_with_new_dangerous_api(tmp_path):
    found, _ = _run(tmp_path, {"index.js": "a()\nexec('x')\n"}, {"index.js": "a()\n"})
    assert found["index.js"].rule_ids == ["IA-CODE-002"]
    assert found["index.js"].diff and "+exec" in found["index.js"].diff


def test_modified_file_plain_change_is_medium(tmp_path):
    found, _ = _run(tmp_path, {"index.js": "a()\nb()\n"}, {"index.js": "a()\n"})
    f = found["index.js"]
    assert (f.verdict, f.severity) == (Verdict.CHANGED, Severity.MEDIUM)
    assert f.rule_ids == ["IA-FILE-002"]


def test_modified_file_that_only_removes_lines_is_low(tmp_path):
    found, _ = _run(tmp_path, {"index.js": "a()\n"}, {"index.js": "// note\na()\n"})
    assert found["index.js"].severity is Severity.LOW


def test_docs_differing_only_in_case_and_whitespace(tmp_path):
    found, counts = _run(
        tmp_path,
        {"readme.md": "# Hello   World\n", "LICENSE": "MIT\n"},
        {"README.md": "# hello world", "LICENSE": "MIT  \n\n"},
    )
    assert found["readme.md"].verdict is Verdict.EXPECTED
    assert found["LICENSE"].verdict is Verdict.EXPECTED
    assert counts["docs"] == 2


def test_unmapped_plain_file_is_medium(tmp_path):
    found, _ = _run(tmp_path, {"extra.js": "module.exports = 1\n"}, {"index.js": ""})
    assert found["extra.js"].rule_ids == ["IA-FILE-001"]
    assert found["extra.js"].severity is Severity.MEDIUM


def test_unmapped_binary_is_medium(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "addon.node").write_bytes(b"\0ELF")
    (tmp_path / "src").mkdir()
    result = classify(compare_trees(pkg, tmp_path / "src"), pkg, tmp_path / "src")
    (f,) = result.findings
    assert f.rule_ids == ["IA-FILE-001"] and "binary" in f.reason


def test_rebuilt_committed_build_output_is_expected(tmp_path):
    found, counts = _run(
        tmp_path,
        {"dist/index.js": "module.exports = 2\n"},
        {"dist/index.js": "module.exports = 1\n", "src/index.ts": "export default 2\n"},
    )
    assert found["dist/index.js"].verdict is Verdict.EXPECTED
    assert counts["build_output"] == 1


def test_build_output_keeps_apis_its_source_uses(tmp_path):
    found, _ = _run(
        tmp_path,
        {"dist/index.js": "eval(code)\n"},
        {"src/index.ts": "eval(code)\n"},
    )
    assert found["dist/index.js"].verdict is Verdict.EXPECTED


def test_entry_point_to_unexplained_file(tmp_path):
    manifest = '{"name": "x", "version": "1.0.0", "main": "%s"}'
    found, _ = _run(
        tmp_path,
        {"package.json": manifest % "lib/payload.js", "lib/payload.js": "module.exports=1\n"},
        {"package.json": manifest % "index.js", "index.js": ""},
    )
    assert "IA-MANIFEST-004" in found["package.json"].rule_ids


def test_registry_manifest_confusion_is_reported(tmp_path):
    manifest = '{"name": "x", "version": "1.0.0"}'
    found, _ = _run(
        tmp_path,
        {"package.json": manifest},
        {"package.json": manifest},
        registry={"scripts": {"postinstall": "node evil.js"}},
    )
    assert found["package.json"].rule_ids == ["IA-MANIFEST-006"]


@pytest.mark.parametrize("bad", ["{not json", "[1, 2]"])
def test_unreadable_package_json_does_not_crash(tmp_path, bad):
    found, _ = _run(tmp_path, {"package.json": bad}, {"package.json": bad})
    assert "package.json" in found


def test_subpath_package_json_stub_is_expected(tmp_path):
    stub = '{"name": "x/ajax", "main": "../dist/cjs/ajax/index.js", "types": "../dist/a.d.ts"}'
    found, counts = _run(tmp_path, {"ajax/package.json": stub}, {"index.js": ""})
    assert found["ajax/package.json"].verdict is Verdict.EXPECTED
    assert counts["subpath_stub"] == 1


def test_nested_package_json_with_scripts_is_not_a_stub(tmp_path):
    nested = '{"name": "x/evil", "scripts": {"postinstall": "node x.js"}}'
    found, _ = _run(tmp_path, {"evil/package.json": nested}, {"index.js": ""})
    assert found["evil/package.json"].verdict is Verdict.SUSPICIOUS


def test_bundle_named_after_package_maps_to_entry(tmp_path):
    manifest = '{"name": "tiny", "version": "1.0.0"}'
    found, counts = _run(
        tmp_path,
        {"package.json": manifest, "dist/tiny.umd.min.js": "var a=1;\n"},
        {"package.json": manifest, "src/index.ts": "export const a = 1;\n"},
    )
    assert found["dist/tiny.umd.min.js"].mapped_source == "src/index.ts"
    assert counts["build_output"] == 1


SHIM = (
    "'use strict';\n\n"
    "if (process.env.NODE_ENV === 'production') {\n"
    "  module.exports = require('./cjs/x.production.js');\n"
    "} else {\n"
    "  module.exports = require('./cjs/x.development.js');\n"
    "}\n"
)
BUILT = {"cjs/x.production.js": "module.exports=1\n", "cjs/x.development.js": "module.exports=1\n"}


def test_entry_switch_replacing_source_entry_is_expected(tmp_path):
    found, counts = _run(tmp_path, {"index.js": SHIM, **BUILT},
                         {"index.js": "export * from './src/x';\n"})
    assert found["index.js"].verdict is Verdict.EXPECTED
    assert "cjs/x.production.js" in found["index.js"].evidence[0]
    assert counts["entry_shim"] == 1


def test_package_only_entry_switch_is_expected(tmp_path):
    found, _ = _run(tmp_path, {"jsx-runtime.js": SHIM, **BUILT}, {"index.js": ""})
    assert found["jsx-runtime.js"].verdict is Verdict.EXPECTED


def test_entry_switch_to_a_missing_file_is_not_expected(tmp_path):
    found, _ = _run(tmp_path, {"index.js": SHIM, "cjs/x.production.js": "1\n"},
                    {"index.js": "export {};\n"})
    assert found["index.js"].verdict is not Verdict.EXPECTED


@pytest.mark.parametrize(
    "extra",
    ["fetch('http://203.0.113.7/x');\n", "require('./evil');\n", "module.exports.x = 1;\n"],
)
def test_entry_switch_with_any_extra_code_is_not_a_switch(tmp_path, extra):
    found, _ = _run(tmp_path, {"index.js": SHIM + extra, **BUILT}, {"index.js": "export {};\n"})
    assert found["index.js"].verdict is not Verdict.EXPECTED


def test_entry_switch_cannot_point_outside_the_package(tmp_path):
    escaping = SHIM.replace("./cjs/x.production.js", "../../etc/x.js")
    found, _ = _run(tmp_path, {"index.js": escaping, **BUILT}, {"index.js": "export {};\n"})
    assert found["index.js"].verdict is not Verdict.EXPECTED


def test_monorepo_license_at_repo_root_is_expected(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "LICENSE").write_text("MIT License\n\nCopyright Meta\n")
    src = repo / "packages" / "react"
    src.mkdir(parents=True)
    (src / "index.js").write_text("")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "LICENSE").write_text("MIT License\nCopyright Meta\n")
    result = classify(compare_trees(pkg, src), pkg, src)
    (lic,) = [f for f in result.findings if f.path == "LICENSE"]
    assert lic.verdict is Verdict.EXPECTED and lic.mapped_source == "../../LICENSE"


def test_repo_root_is_not_searched_outside_a_git_repo(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT\n")
    src = tmp_path / "a" / "b"
    src.mkdir(parents=True)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "LICENSE").write_text("MIT\n")
    result = classify(compare_trees(pkg, src), pkg, src)
    (lic,) = [f for f in result.findings if f.path == "LICENSE"]
    assert lic.verdict is Verdict.CHANGED and lic.severity is Severity.LOW


def test_documentation_changes_are_low(tmp_path):
    found, _ = _run(tmp_path, {"README.md": "See https://old.example\n"},
                    {"README.md": "See https://new.example\n"})
    assert (found["README.md"].verdict, found["README.md"].severity) == (
        Verdict.CHANGED, Severity.LOW)


def test_documentation_with_command_examples_is_not_code(tmp_path):
    found, _ = _run(tmp_path, {"README.md": "Install: `curl -sL https://x.sh | sh`\n"},
                    {"README.md": "Install with npm\n"})
    assert found["README.md"].severity is Severity.LOW


def test_code_named_like_a_document_is_still_code(tmp_path):
    found, _ = _run(tmp_path, {"README.js": "require('child_process').exec('x')\n"},
                    {"index.js": ""})
    assert found["README.js"].severity is Severity.HIGH
