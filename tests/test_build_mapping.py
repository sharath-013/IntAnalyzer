import pytest

from intanalyze.rules.build_mapping import is_code, map_to_source, strip_output_ext

SOURCES = {
    "src/index.ts",
    "src/util/strings.tsx",
    "src/cli.mts",
    "index.ts",
    "packages/a/src/main.js",
}


@pytest.mark.parametrize(
    ("published", "source"),
    [
        ("dist/index.js", "src/index.ts"),
        ("dist/index.d.ts", "src/index.ts"),
        ("dist/index.js.map", "src/index.ts"),
        ("dist/index.d.ts.map", "src/index.ts"),
        ("lib/util/strings.js", "src/util/strings.tsx"),
        ("esm/util/strings.mjs", "src/util/strings.tsx"),
        ("dist/cjs/index.cjs", "src/index.ts"),
        ("dist/esm/util/strings.js", "src/util/strings.tsx"),
        ("build/cli.mjs", "src/cli.mts"),
        ("out/cli.d.mts", "src/cli.mts"),
        ("packages/a/dist/main.js", "packages/a/src/main.js"),
    ],
)
def test_maps_build_output(published, source):
    assert map_to_source(published, SOURCES) == source


@pytest.mark.parametrize(
    "published",
    ["lib/x.min.js", "dist/evil.js", "index.js", "dist/index.css", "src/index.js", "dist/"],
)
def test_unmapped(published):
    assert map_to_source(published, SOURCES) is None


def test_root_level_typescript_compiles_to_dist():
    assert map_to_source("dist/index.js", {"index.ts"}) == "index.ts"


def test_helpers():
    assert strip_output_ext("a/b.d.ts.map") == "a/b"
    assert strip_output_ext("a/b.css") is None
    assert is_code("x.cjs") and not is_code("x.d.ts")
