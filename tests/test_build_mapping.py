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
    ["lib/x.min.js", "dist/evil.js", "payload.js", "dist/index.css", "src/index.js", "dist/"],
)
def test_unmapped(published):
    assert map_to_source(published, SOURCES) is None


def test_root_level_typescript_compiles_to_dist():
    assert map_to_source("dist/index.js", {"index.ts"}) == "index.ts"


def test_helpers():
    assert strip_output_ext("a/b.d.ts.map") == "a/b"
    assert strip_output_ext("a/b.css") is None
    assert is_code("x.cjs") and not is_code("x.d.ts")


@pytest.mark.parametrize(
    ("published", "source"),
    [
        ("dist/esm5/internal/Observable.js", "src/internal/Observable.ts"),
        ("dist/types/internal/Observable.d.ts", "src/internal/Observable.ts"),
        ("dist/esm2015/internal/Observable.js.map", "src/internal/Observable.ts"),
        ("lib/node/es/internal/Observable.mjs", "src/internal/Observable.ts"),
    ],
)
def test_any_build_flavour_folder_under_the_output_dir(published, source):
    assert map_to_source(published, {"src/internal/Observable.ts"}) == source


@pytest.mark.parametrize(
    "bundle",
    ["dist/bundles/rxjs.umd.min.js", "dist/rxjs.esm.mjs", "dist/index.production.cjs",
     "dist/umd/rxjs.umd.js.map"],
)
def test_bundles_named_after_the_package_map_to_the_entry(bundle):
    assert map_to_source(bundle, {"src/index.ts"}, package_name="rxjs") == "src/index.ts"


def test_scoped_package_bundle():
    assert map_to_source("dist/core.cjs", {"src/index.ts"}, "@acme/core") == "src/index.ts"


@pytest.mark.parametrize("payload", ["lib/x.min.js", "dist/payload.js", "dist/evil.umd.js"])
def test_unrelated_names_are_not_treated_as_bundles(payload):
    assert map_to_source(payload, {"src/index.ts"}, package_name="rxjs") is None


@pytest.mark.parametrize(
    ("published", "sources", "expected"),
    [
        ("formatRFC7231.cjs", {"src/formatRFC7231/index.ts"}, "src/formatRFC7231/index.ts"),
        ("locale/af.js", {"src/locale/af.js"}, "src/locale/af.js"),
        ("dayjs.min.js", {"src/index.js"}, "src/index.js"),
        ("cjs/react-jsx-runtime.production.min.js", {"jsx-runtime.js"}, "jsx-runtime.js"),
        ("index.js", {"index.ts"}, "index.ts"),  # plain tsc output next to its source
        ("payload.js", {"index.ts", "src/index.ts"}, None),  # unrelated root file
    ],
)
def test_root_level_output_and_entry_bundles(published, sources, expected):
    name = "react" if "react" in published else "dayjs"
    assert map_to_source(published, sources, name) == expected


@pytest.mark.parametrize(
    ("published", "expected"),
    [
        ("cdn.min.js", "src/index.ts"),
        ("locale/af/cdn.js", "src/locale/af/index.ts"),
        ("umd/react.production.min.js", "src/index.ts"),
    ],
)
def test_cdn_and_umd_bundles(published, expected):
    sources = {"src/index.ts", "src/locale/af/index.ts"}
    assert map_to_source(published, sources, "react") == expected
