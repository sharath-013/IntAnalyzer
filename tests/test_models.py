import pytest

from intanalyze.models import Finding, PackageSpec, Relationship, Report, Severity, Verdict


@pytest.mark.parametrize(
    ("spec", "name", "version"),
    [
        ("ms@2.1.3", "ms", "2.1.3"),
        ("@types/node@20.11.0", "@types/node", "20.11.0"),
        ("  lodash@4.17.21 ", "lodash", "4.17.21"),
        ("pkg@1.0.0-beta.1", "pkg", "1.0.0-beta.1"),
    ],
)
def test_parse_spec(spec, name, version):
    parsed = PackageSpec.parse(spec)
    assert (parsed.name, parsed.version) == (name, version)
    assert str(parsed) == f"{name}@{version}"


@pytest.mark.parametrize("bad", ["ms", "ms@", "@types/node", "@", "../evil@1.0.0", ""])
def test_parse_spec_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        PackageSpec.parse(bad)


def test_severity_rank_orders_levels():
    ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4


def test_report_round_trips_through_json():
    report = Report(
        tool_version="0.1.0",
        package=PackageSpec.parse("ms@2.1.3"),
        findings=[
            Finding(
                path="package.json",
                verdict=Verdict.SUSPICIOUS,
                severity=Severity.HIGH,
                relationship=Relationship.MODIFIED,
                rule_ids=["IA-MANIFEST-001"],
                reason="new postinstall script",
            )
        ],
    )
    again = Report.model_validate_json(report.model_dump_json())
    assert again == report
    assert again.findings[0].explanation_source == "rules"
