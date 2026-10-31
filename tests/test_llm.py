"""LLM client tests: all HTTP is mocked with respx; no LM Studio needed."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from intanalyze.llm import (
    MAX_CONTEXT_CHARS,
    FakeLLM,
    LLMError,
    LLMUnavailable,
    LMStudioClient,
    explain_report,
    extract_json,
    finding_context,
    llm_model,
    llm_url,
    rule_summary,
    strip_think,
)
from intanalyze.models import Finding, Relationship, Severity, Verdict
from intanalyze.pipeline import check_offline

FIXTURES = Path(__file__).parent / "fixtures"
URL = "http://llm.test/v1"
CHAT = f"{URL}/chat/completions"
GOOD = {"summary": "s", "why_it_matters": "w", "recommended_action": "a"}


def _reply(content, model="qwen/qwen3.5-9b"):
    message = {"role": "assistant", "content": content}
    return httpx.Response(200, json={"model": model, "choices": [{"message": message}]})


def _finding(**over):
    data = dict(
        path="package.json", verdict=Verdict.SUSPICIOUS, severity=Severity.HIGH,
        relationship=Relationship.MODIFIED, rule_ids=["IA-MANIFEST-001"], reason="new postinstall",
        evidence=['scripts.postinstall = "node x.js"'],
    )
    data.update(over)
    return Finding(**data)


def _report(name="malicious"):
    d = FIXTURES / name
    return check_offline(d / "package.tgz", d / "source", registry_json=d / "registry.json")


@pytest.fixture
def client():
    c = LMStudioClient(URL, "qwen/qwen3.5-9b")
    yield c
    c.close()


def test_env_overrides(monkeypatch):
    monkeypatch.delenv("INTANALYZE_LLM_URL", raising=False)
    monkeypatch.delenv("INTANALYZE_MODEL", raising=False)
    assert llm_url() == "http://localhost:1234/v1" and llm_model() == "qwen/qwen3.5-9b"
    monkeypatch.setenv("INTANALYZE_LLM_URL", "http://box:9999/v1/")
    monkeypatch.setenv("INTANALYZE_MODEL", "other")
    assert llm_url() == "http://box:9999/v1" and llm_model() == "other"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<think>hmm {not json}</think>\n{\"a\": 1}", {"a": 1}),
        ('<THINK>x</THINK>Here you go: ```json\n{"a": {"b": 2}}\n```', {"a": {"b": 2}}),
        ('{"a": "brace } in string"} trailing', {"a": "brace } in string"}),
        ('</think>{"a": 3}', {"a": 3}),
        ('{bad} then {"a": 4}', {"a": 4}),
    ],
)
def test_think_stripping_and_json_extraction(raw, expected):
    assert extract_json(raw) == expected


def test_unclosed_think_is_dropped():
    assert strip_think('{"a": 1}<think>still thinking') == '{"a": 1}'
    with pytest.raises(LLMError):
        extract_json("<think>only thoughts")


def test_finding_context_is_capped():
    huge = _finding(diff="+" + "x" * 20000)
    ctx = finding_context(huge)
    assert len(ctx) <= MAX_CONTEXT_CHARS and ctx.endswith("[truncated]")
    assert "Verdict (final): SUSPICIOUS" in finding_context(_finding())


@respx.mock
def test_explain_sends_json_schema_and_records_model(client):
    route = respx.post(CHAT).mock(return_value=_reply("<think>ok</think>" + json.dumps(GOOD)))
    exp = client.explain(_finding(), "ctx")
    assert exp.summary == "s" and client.answered_model == "qwen/qwen3.5-9b"
    body = json.loads(route.calls[0].request.content)
    assert body["model"] == "qwen/qwen3.5-9b" and body["temperature"] == 0
    assert body["max_tokens"] == 800
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["name"] == "explanation"
    assert "Authorization" not in route.calls[0].request.headers


@respx.mock
def test_response_format_rejected_retries_without_it(client):
    route = respx.post(CHAT).mock(
        side_effect=[httpx.Response(400, json={"error": "bad"}), _reply(json.dumps(GOOD))]
    )
    assert client.explain(_finding(), "ctx").summary == "s"
    assert "response_format" not in json.loads(route.calls[1].request.content)


@respx.mock
def test_invalid_json_retries_once_then_succeeds(client):
    route = respx.post(CHAT).mock(side_effect=[_reply("no json here"), _reply(json.dumps(GOOD))])
    assert client.explain(_finding(), "ctx").why_it_matters == "w"
    assert len(route.calls) == 2


@respx.mock
def test_invalid_json_twice_raises(client):
    respx.post(CHAT).mock(side_effect=[_reply("nope"), _reply('{"summary": "missing fields"}')])
    with pytest.raises(LLMError, match="invalid answer"):
        client.explain(_finding(), "ctx")


@respx.mock
def test_server_unreachable(client):
    respx.post(CHAT).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(LLMUnavailable):
        client.explain(_finding(), "ctx")
    respx.get(f"{URL}/models").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(LLMUnavailable):
        client.models()


@respx.mock
@pytest.mark.parametrize(
    "response",
    [httpx.Response(500), httpx.Response(200, json={"choices": []}), httpx.ReadTimeout("slow")],
)
def test_bad_server_responses(client, response):
    if isinstance(response, Exception):
        respx.post(CHAT).mock(side_effect=response)
    else:
        respx.post(CHAT).mock(return_value=response)
    with pytest.raises(LLMError):
        client.explain(_finding(), "ctx")


@respx.mock
def test_models_health_check(client):
    respx.get(f"{URL}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "qwen/qwen3.5-9b"}]})
    )
    assert client.models() == ["qwen/qwen3.5-9b"]
    respx.get(f"{URL}/models").mock(return_value=httpx.Response(503))
    with pytest.raises(LLMError):
        client.models()


@respx.mock
def test_summarize(client):
    respx.post(CHAT).mock(return_value=_reply('{"summary": "Release looks risky."}'))
    assert client.summarize(_report()) == "Release looks risky."


def test_explain_report_with_fake_llm():
    report = _report()
    fake = FakeLLM()
    progress = []
    explain_report(report, fake, on_progress=lambda i, n: progress.append((i, n)))
    flagged = [f for f in report.findings if f.verdict is not Verdict.EXPECTED]
    assert all(f.explanation_source == "llm" for f in flagged)
    assert all(f.explanation_source == "rules" for f in report.findings if f not in flagged)
    assert sorted(fake.calls) == sorted(f.path for f in flagged)
    assert progress[-1] == (len(flagged), len(flagged))
    assert report.llm.used and report.llm.model == "fake-llm"
    assert report.summary.startswith("[fake]")


def test_llm_never_changes_verdicts():
    plain, explained = _report(), _report()
    explain_report(explained, FakeLLM())
    assert [(f.path, f.verdict, f.severity) for f in plain.findings] == [
        (f.path, f.verdict, f.severity) for f in explained.findings
    ]
    assert plain.score == explained.score and plain.status == explained.status


def test_explain_report_cap():
    fake = FakeLLM()
    explain_report(_report(), fake, limit=1)
    assert len(fake.calls) == 1


def test_explain_report_disabled():
    report = explain_report(_report(), None)
    assert report.llm.used is False and "--no-llm" in report.llm.reason
    assert report.summary == rule_summary(report)


class _Down(FakeLLM):
    def explain(self, finding, context):
        raise LLMUnavailable("server down")

    def summarize(self, report):
        raise LLMUnavailable("server down")


class _Garbage(FakeLLM):
    def explain(self, finding, context):
        raise LLMError("bad json")

    def summarize(self, report):
        raise LLMError("bad json")


def test_unreachable_server_falls_back_with_one_warning():
    warnings = []
    report = explain_report(_report(), _Down(), warn=warnings.append)
    assert len(warnings) == 1
    assert report.llm.used is False and report.llm.reason == "server down"
    assert all(f.explanation_source == "rules" for f in report.findings)
    assert report.summary == rule_summary(report)


def test_garbage_answers_fall_back_to_rule_text():
    report = explain_report(_report(), _Garbage())
    assert report.llm.used is False and "no usable" in report.llm.reason
    assert all(f.explanation is not None for f in report.findings)


def test_rule_summary_clean():
    assert "matches its source" in rule_summary(_report("clean"))


@respx.mock
def test_answer_in_reasoning_content_is_used(client):
    message = {"role": "assistant", "content": "", "reasoning_content": json.dumps(GOOD)}
    respx.post(CHAT).mock(
        return_value=httpx.Response(200, json={"model": "m", "choices": [{"message": message}]})
    )
    assert client.explain(_finding(), "ctx").recommended_action == "a"
