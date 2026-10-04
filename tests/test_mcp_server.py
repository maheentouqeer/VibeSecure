"""MCP server tests using the SDK's in-memory client, so the real protocol
(tool listing, argument validation, structured results) is exercised."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import mcp_server


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("orchestrator.run_semgrep", lambda path: [])


def _call(tool, args):
    async def go():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as client:
            return await client.call_tool(tool, args)

    return asyncio.run(go())


def _payload(result):
    if result.structuredContent is not None:
        return result.structuredContent.get("result", result.structuredContent)
    return json.loads(result.content[0].text)


async def _scan_and_wait(client, tool, args):
    result = await client.call_tool(tool, args)
    data = _payload(result)
    if "scan_id" not in data or data.get("status") not in {"queued", "running"}:
        return data
    scan_id = data["scan_id"]
    for _ in range(100):
        status_result = await client.call_tool("get_scan_status", {"scan_id": scan_id})
        status = _payload(status_result)
        if status["status"] == "completed":
            return _payload(await client.call_tool("get_findings", {"scan_id": scan_id}))
        if status["status"] == "failed":
            raise AssertionError(status.get("error") or "MCP scan failed")
        await asyncio.sleep(0.01)
    raise AssertionError("MCP scan did not complete in test timeout")


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "aws.ts").write_text("const key = 'AKIA1234567890ABCDEF';")
    return tmp_path


def test_server_exposes_the_mcp_tools():
    async def go():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)

    assert asyncio.run(go()) == [
        "get_findings", "get_scan_status", "rescan",
        "scan_live_url", "scan_local_workspace", "scan_repository",
        "scan_url", "scan_workspace", "verify_fixes",
    ]


def test_scan_workspace_finds_secret_and_returns_actionable_fields(project):
    async def go():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as client:
            return await _scan_and_wait(client, "scan_workspace", {"path": str(project)})

    data = asyncio.run(go())

    assert data["platform"] == "generic"
    assert data["summary"]["critical"] == 1
    finding = data["findings"][0]
    assert finding["label"] == "AWS Access Key"
    assert finding["file"] == "src/aws.ts"
    assert finding["fingerprint"] and finding["fix_prompt"] and finding["what_it_means"]
    assert "1234567890ABCDEF" not in json.dumps(data)  # the secret itself never leaves the scanner


def test_verify_fixes_reports_resolved_and_new_findings(project):
    async def go():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as client:
            first = await _scan_and_wait(client, "scan_workspace", {"path": str(project)})
            fingerprints = [f["fingerprint"] for f in first["findings"]]

            (project / "src" / "aws.ts").write_text("const key = process.env.AWS_KEY;")
            (project / "src" / "stripe.ts").write_text("const s = 'sk_test_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3" + "';")
            return await _scan_and_wait(client, "verify_fixes", {"path": str(project), "fingerprints": fingerprints}), fingerprints

    after, fingerprints = asyncio.run(go())

    assert after["resolved"] == fingerprints
    assert after["still_present"] == []
    assert [f["label"] for f in after["new_findings"]] == ["Stripe Secret Key"]


def test_verify_fixes_reports_still_present_when_nothing_changed(project):
    async def go():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as client:
            first = await _scan_and_wait(client, "scan_workspace", {"path": str(project)})
            fingerprints = [f["fingerprint"] for f in first["findings"]]
            after = await _scan_and_wait(client, "verify_fixes", {"path": str(project), "fingerprints": fingerprints})
            return after, fingerprints

    after, fingerprints = asyncio.run(go())
    assert after["still_present"] == fingerprints and after["resolved"] == []


def test_scan_workspace_rejects_a_path_that_is_not_a_directory(project):
    result = _call("scan_workspace", {"path": str(project / "does-not-exist")})
    assert result.isError is True
    assert "not a directory" in result.content[0].text


def test_scan_url_uses_the_ssrf_guard(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    result = _call("scan_url", {"target": "http://169.254.169.254/latest/meta-data/"})
    assert result.isError is True
    assert "not allowed" in result.content[0].text
