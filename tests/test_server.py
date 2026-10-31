"""The local web UI: a real server on a free loopback port, driven over HTTP (no network)."""

import threading
import time

import httpx
import pytest

from intanalyze import server
from intanalyze.llm import FakeLLM
from intanalyze.models import PackageSpec
from intanalyze.pipeline import CheckError


class _FakeClient(FakeLLM):
    model = "fake-llm"

    def __init__(self, **kw):
        super().__init__()

    def models(self):
        return ["fake-llm"]


class _DownClient(_FakeClient):
    server = "http://127.0.0.1:9/v1"

    def models(self):
        from intanalyze.llm import LLMUnavailable

        raise LLMUnavailable("LM Studio server not reachable")


@pytest.fixture
def ui(monkeypatch):
    monkeypatch.setattr(server, "make_llm_client", _FakeClient)
    httpd = server.make_server(0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    with httpx.Client(base_url=f"http://127.0.0.1:{httpd.server_address[1]}", timeout=10) as c:
        yield c
    httpd.shutdown()
    httpd.server_close()


def _wait(ui, job_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = ui.get(f"/api/jobs/{job_id}").json()
        if job["state"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_page_is_served_with_a_strict_csp(ui):
    r = ui.get("/")
    assert r.status_code == 200 and "<title>IntAnalyze</title>" in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    # The page builds the DOM from package data with textContent, never innerHTML.
    assert "innerHTML" not in r.text
    assert ui.head("/").status_code == 200


def test_status(ui):
    s = ui.get("/api/status").json()
    assert s["llm"]["reachable"] and s["llm"]["model_loaded"]
    assert s["fixtures"] == ["clean", "malicious"]
    assert s["version"]


def test_status_when_model_is_down(ui, monkeypatch):
    monkeypatch.setattr(server, "make_llm_client", _DownClient)
    s = ui.get("/api/status").json()
    assert s["llm"]["reachable"] is False and "not reachable" in s["llm"]["error"]


def test_malicious_fixture_end_to_end_with_llm(ui):
    r = ui.post("/api/check", json={"fixture": "malicious", "llm": True})
    assert r.status_code == 202
    job = _wait(ui, r.json()["id"])
    assert job["state"] == "done" and job["exit_code"] == 1
    report = job["report"]
    assert report["status"] == "DANGEROUS" and report["llm"]["model"] == "fake-llm"
    assert "explaining findings with fake-llm" in job["steps"] and job["steps"][-1] == "done"
    assert job["explained"]["done"] == job["explained"]["total"] == 3
    html = ui.get(f"/api/jobs/{job['id']}/report.html")
    assert html.status_code == 200 and "<!doctype html>" in html.text
    js = ui.get(f"/api/jobs/{job['id']}/report.json")
    assert js.json()["status"] == "DANGEROUS"
    assert 'filename="intanalyze-tiny-percent-1.0.0.json"' in js.headers["content-disposition"]
    md = ui.get(f"/api/jobs/{job['id']}/report.md")
    assert md.text.startswith("# IntAnalyze report")
    assert ui.get(f"/api/jobs/{job['id']}/report.exe").status_code == 404


def test_clean_fixture_without_llm_and_fail_on(ui):
    r = ui.post("/api/check", json={"fixture": "clean", "llm": False, "fail_on": "low"})
    job = _wait(ui, r.json()["id"])
    assert job["report"]["status"] == "CLEAN" and job["exit_code"] == 0
    assert job["report"]["llm"]["used"] is False


def test_model_down_falls_back_to_rules(ui, monkeypatch):
    monkeypatch.setattr(server, "make_llm_client", _DownClient)
    job = _wait(ui, ui.post("/api/check", json={"fixture": "malicious"}).json()["id"])
    assert job["report"]["status"] == "DANGEROUS"
    assert job["report"]["llm"]["used"] is False
    assert any("using rule explanations only" in s for s in job["steps"])


def test_online_check_uses_the_pipeline(ui, monkeypatch):
    seen = {}

    def fake_online(spec, progress):
        seen["spec"] = spec
        progress("resolving")
        raise CheckError("no source repository declared")

    monkeypatch.setattr(server, "check_online", fake_online)
    job = _wait(ui, ui.post("/api/check", json={"spec": "@scope/pkg@1.0.0"}).json()["id"])
    assert seen["spec"] == PackageSpec.parse("@scope/pkg@1.0.0")
    assert job["state"] == "error" and job["exit_code"] == 2
    assert job["error"] == "no source repository declared"


def test_unexpected_errors_are_reported_not_raised(ui, monkeypatch):
    def boom(spec, progress):
        raise RuntimeError("disk full")

    monkeypatch.setattr(server, "check_online", boom)
    job = _wait(ui, ui.post("/api/check", json={"spec": "ms@2.1.3"}).json()["id"])
    assert job["state"] == "error" and "disk full" in job["error"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({}, "either a package"),
        ({"spec": "ms@2.1.3", "fixture": "clean"}, "either a package"),
        ({"spec": "not a spec"}, "<name>@<version>"),
        ({"spec": 42}, "package must be text"),
        ({"fixture": "../etc"}, "unknown demo fixture"),
        ({"spec": "ms@2.1.3", "fail_on": "sometimes"}, "fail_on"),
        ([1, 2], "JSON object"),
    ],
)
def test_bad_requests(ui, body, message):
    r = ui.post("/api/check", json=body)
    assert r.status_code == 400 and message in r.json()["error"]


def test_post_requires_json_and_a_sane_body(ui):
    assert ui.post("/api/check", content=b"spec=ms", headers={
        "Content-Type": "application/x-www-form-urlencoded"}).status_code == 415
    assert ui.post("/api/check", content=b"{not json", headers={
        "Content-Type": "application/json"}).status_code == 400
    big = b'{"spec": "' + b"a" * 20_000 + b'"}'
    assert ui.post("/api/check", content=big, headers={
        "Content-Type": "application/json"}).status_code == 400
    assert ui.post("/api/other", json={}).status_code == 404


def test_foreign_host_header_is_refused(ui):
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 must get nothing."""
    assert ui.get("/api/status", headers={"Host": "evil.example:8787"}).status_code == 403
    assert ui.post("/api/check", json={"fixture": "clean"},
                   headers={"Host": "evil.example"}).status_code == 403
    assert ui.get("/", headers={"Host": "localhost:8787"}).status_code == 200
    assert ui.get("/", headers={"Host": "[::1]:8787"}).status_code == 200


def test_unknown_routes_and_jobs(ui):
    assert ui.get("/nope").status_code == 404
    assert ui.get("/api/jobs/abc").status_code == 404


def test_job_store_forgets_the_oldest():
    store = server.JobStore()
    first = store.add("a")
    for i in range(server.MAX_JOBS):
        store.add(str(i))
    assert store.get(first.id) is None


def test_fixtures_unavailable_outside_a_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "fixtures_dir", lambda: None)
    with pytest.raises(ValueError, match="source checkout"):
        server.parse_request({"fixture": "clean"})


def test_server_binds_loopback_only():
    httpd = server.make_server(0)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
    finally:
        httpd.server_close()
