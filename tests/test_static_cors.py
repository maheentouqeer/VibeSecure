from scanner.cors_scanner import check_static_cors


def _write(repo, rel, text):
    f = repo / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def test_static_cors_detects_wildcard_cors_call(tmp_path):
    _write(tmp_path, "server.js", 'app.use(cors({ origin: "*" }));\n')
    findings = check_static_cors(tmp_path)
    assert len(findings) == 1
    assert findings[0]["category"] == "cors_misconfig"
    assert findings[0]["label"] == "CORS allows any origin (*)"
    assert findings[0]["file"] == "server.js"


def test_static_cors_detects_wildcard_response_header(tmp_path):
    _write(tmp_path, "api.ts", 'res.setHeader("Access-Control-Allow-Origin", "*");\n')
    findings = check_static_cors(tmp_path)
    assert len(findings) == 1
    assert findings[0]["file"] == "api.ts"


def test_static_cors_ignores_specific_origin(tmp_path):
    _write(tmp_path, "server.js", 'app.use(cors({ origin: "https://example.com" }));\n')
    assert check_static_cors(tmp_path) == []