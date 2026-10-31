"""Local web UI: ``intanalyze serve`` serves one page and a small JSON API on 127.0.0.1.

Standard library only (``http.server``), so the UI adds no dependencies. Checks run in a
background thread per job and the page polls for progress. The server listens on loopback
only, rejects other ``Host`` headers (DNS rebinding) and only accepts JSON POSTs (which a
foreign web page cannot send without a CORS preflight this server never answers).
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from intanalyze import __version__
from intanalyze.llm import LLMError, LMStudioClient, explain_checked, explain_report
from intanalyze.models import PackageSpec, Report
from intanalyze.pipeline import CheckError, check_offline, check_online
from intanalyze.report import render_html, render_json, render_markdown
from intanalyze.score import FAIL_ON, exit_code

DEFAULT_PORT = 8787
MAX_BODY = 10_000
MAX_JOBS = 20
FIXTURE_NAMES = ("clean", "malicious")
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})

# Factory for the LLM client; tests swap in a fake.
make_llm_client = LMStudioClient


def fixtures_dir() -> Path | None:
    """The repo's demo fixtures, if this is a source checkout (or INTANALYZE_FIXTURES)."""
    candidates = [
        os.environ.get("INTANALYZE_FIXTURES"),
        Path.cwd() / "tests" / "fixtures",
        Path(__file__).resolve().parents[2] / "tests" / "fixtures",
    ]
    for cand in candidates:
        if cand and (Path(cand) / "malicious" / "package.tgz").is_file():
            return Path(cand)
    return None


@dataclass
class Job:
    id: str
    label: str
    state: str = "running"  # running | done | error
    steps: list[str] = field(default_factory=list)
    explained: tuple[int, int] = (0, 0)
    report: Report | None = None
    error: str | None = None
    exit_code: int | None = None
    started: float = field(default_factory=time.time)
    finished: float | None = None

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "state": self.state,
            "steps": list(self.steps),
            "explained": {"done": self.explained[0], "total": self.explained[1]},
            "error": self.error,
            "exit_code": self.exit_code,
            "seconds": round((self.finished or time.time()) - self.started, 1),
            "report": self.report.model_dump(mode="json") if self.report else None,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def add(self, label: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], label=label)
        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > MAX_JOBS:  # forget the oldest
                self._jobs.pop(next(iter(self._jobs)))
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)


def parse_request(body: dict) -> dict:
    """Validate a check request; raises ValueError with a message for the page."""
    if not isinstance(body, dict):
        raise ValueError("expected a JSON object")
    fixture, spec = body.get("fixture"), body.get("spec")
    if bool(fixture) == bool(spec):
        raise ValueError("give either a package (name@version) or a demo fixture")
    fail_on = body.get("fail_on", "high")
    if fail_on not in (*FAIL_ON, "never"):
        raise ValueError("fail_on must be one of high, medium, low, never")
    req = {"llm": bool(body.get("llm", True)), "fail_on": fail_on}
    if fixture:
        if fixture not in FIXTURE_NAMES:
            raise ValueError(f"unknown demo fixture {fixture!r}")
        if fixtures_dir() is None:
            raise ValueError("demo fixtures are only available in a source checkout")
        req["fixture"] = fixture
    else:
        if not isinstance(spec, str):
            raise ValueError("package must be text like ms@2.1.3")
        req["spec"] = PackageSpec.parse(spec)  # ValueError on bad input
    return req


def run_job(job: Job, req: dict) -> None:
    """Run one check; every outcome ends up on the job, never as an exception."""
    try:
        if "fixture" in req:
            d = fixtures_dir()
            assert d is not None
            name = req["fixture"]
            report = check_offline(
                d / name / "package.tgz",
                d / name / "source",
                registry_json=d / name / "registry.json",
                progress=job.steps.append,
            )
        else:
            report = check_online(req["spec"], progress=job.steps.append)

        if req["llm"]:
            client = make_llm_client()
            job.steps.append(f"explaining findings with {client.model}")
            try:
                explain_checked(
                    report,
                    client,
                    on_progress=lambda done, total: setattr(job, "explained", (done, total)),
                    warn=job.steps.append,
                )
            finally:
                close = getattr(client, "close", None)
                if close:
                    close()
        else:
            explain_report(report, None)

        job.report = report
        job.exit_code = exit_code(report.findings, req["fail_on"])
        job.steps.append("done")
        job.state = "done"
    except CheckError as exc:
        job.error, job.exit_code, job.state = str(exc), 2, "error"
    except Exception as exc:  # noqa: BLE001 - surface anything to the page, keep serving
        job.error, job.exit_code, job.state = f"unexpected error: {exc}", 2, "error"
    finally:
        job.finished = time.time()


def status_info() -> dict:
    """What the page's header shows: versions, the LLM server, and demo availability."""
    client = make_llm_client()
    info: dict = {
        "version": __version__,
        "python": platform.python_version(),
        "llm": {"server": client.server, "model": client.model, "reachable": False,
                "loaded": [], "model_loaded": False, "error": None},
        "fixtures": list(FIXTURE_NAMES) if fixtures_dir() else [],
    }
    try:
        info["git"] = subprocess.run(
            ["git", "--version"], capture_output=True, text=True, timeout=10, check=False
        ).stdout.strip()
    except OSError:
        info["git"] = None
    try:
        loaded = client.models()
        info["llm"].update(reachable=True, loaded=loaded, model_loaded=client.model in loaded)
    except LLMError as exc:
        info["llm"]["error"] = str(exc)
    finally:
        close = getattr(client, "close", None)
        if close:
            close()
    return info


class Handler(BaseHTTPRequestHandler):
    server_version = f"intanalyze/{__version__}"
    jobs: JobStore  # set by make_server

    # -- plumbing ---------------------------------------------------------------------
    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # keep the terminal quiet; errors are shown in the page

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            name = host.split("]")[0] + "]"
        else:
            name = host.rsplit(":", 1)[0]
        return name in ALLOWED_HOSTS

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data).encode(), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    # -- routes -----------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "requests must use localhost")
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            page = resources.files("intanalyze").joinpath("web/index.html").read_bytes()
            return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
        if path == "/api/status":
            return self._json(HTTPStatus.OK, status_info())
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
            job = self.jobs.get(parts[2])
            if job is None:
                return self._error(HTTPStatus.NOT_FOUND, "no such check")
            if len(parts) == 3:
                return self._json(HTTPStatus.OK, job.to_json())
            if len(parts) == 4 and job.report is not None:
                return self._download(job, parts[3])
        return self._error(HTTPStatus.NOT_FOUND, "not found")

    do_HEAD = do_GET

    def _download(self, job: Job, name: str) -> None:
        assert job.report is not None
        pkg = job.report.package
        base = f"intanalyze-{pkg.name.replace('/', '-').lstrip('@')}-{pkg.version}"
        if name == "report.html":
            return self._send(HTTPStatus.OK, render_html(job.report).encode(),
                              "text/html; charset=utf-8")
        if name == "report.json":
            return self._send(HTTPStatus.OK, render_json(job.report).encode(),
                              "application/json; charset=utf-8",
                              {"Content-Disposition": f'attachment; filename="{base}.json"'})
        if name == "report.md":
            return self._send(HTTPStatus.OK, render_markdown(job.report).encode(),
                              "text/markdown; charset=utf-8",
                              {"Content-Disposition": f'attachment; filename="{base}.md"'})
        return self._error(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "requests must use localhost")
        if self.path != "/api/check":
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send JSON")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            return self._error(HTTPStatus.BAD_REQUEST, "request body missing or too large")
        try:
            req = parse_request(json.loads(self.rfile.read(length)))
        except ValueError as exc:  # includes JSON decode errors
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        label = f"{req['fixture']} demo fixture" if "fixture" in req else str(req["spec"])
        job = self.jobs.add(label)
        threading.Thread(target=run_job, args=(job, req), daemon=True).start()
        self._json(HTTPStatus.ACCEPTED, {"id": job.id})


def make_server(port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """A server bound to loopback only; port 0 picks a free port (tests)."""
    handler = type("BoundHandler", (Handler,), {"jobs": JobStore()})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    return httpd


def serve(port: int = DEFAULT_PORT, open_browser: bool = True) -> None:  # pragma: no cover
    httpd = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"IntAnalyze UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
