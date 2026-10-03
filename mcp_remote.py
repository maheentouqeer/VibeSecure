"""Authenticated remote Streamable HTTP MCP surface for VibeSecure.

Unlike the local stdio server, this surface never accepts an arbitrary local
filesystem path. Every request requires X-API-Key and every scan is tied to
that account in the existing database-backed job system.
"""
from __future__ import annotations

import anyio
from mcp.server.fastmcp import FastMCP
from starlette.types import ASGIApp, Receive, Scope, Send

from backend import api_keys, db, jobs, plans
from backend.auth import Actor

mcp = FastMCP("VibeSecure Remote", json_response=True, stateless_http=True, streamable_http_path="/")

def _enqueue(user_id: str, target: str, kind: str) -> str:
    with db.SessionLocal() as session:
        user = session.get(db.User, user_id)
        if user is None:
            raise ValueError("MCP account no longer exists.")
        plans.enforce_monthly_limit(session, Actor(user=user, owner_token=None))
        scan = db.Scan(
            target=target, platform="generic", status="queued",
            owner_token=f"mcp-{user.id}", owner_user_id=user.id,
        )
        session.add(scan)
        session.flush()
        session.add(db.ScanRun(
            scan_id=scan.id, kind=kind, owner_user_id=user.id, owner_token=scan.owner_token
        ))
        job = jobs.enqueue(session, scan.id, kind)
        session.commit()
    if jobs.inline():
        jobs.submit(job.id)
    return scan.id

def _status(user_id: str, scan_id: str) -> dict:
    with db.SessionLocal() as session:
        scan = (
            session.query(db.Scan)
            .filter(db.Scan.id == scan_id, db.Scan.owner_user_id == user_id)
            .one_or_none()
        )
        if scan is None:
            raise ValueError("Scan not found.")
        return {
            "scan_id": scan.id, "target": scan.target, "platform": scan.platform,
            "status": scan.status, "error": scan.error, "finding_count": len(scan.findings),
        }

def _findings(user_id: str, scan_id: str) -> dict:
    with db.SessionLocal() as session:
        scan = (
            session.query(db.Scan)
            .filter(db.Scan.id == scan_id, db.Scan.owner_user_id == user_id)
            .one_or_none()
        )
        if scan is None:
            raise ValueError("Scan not found.")
        findings = [
            {
                "fingerprint": f.fingerprint, "category": f.category, "label": f.label,
                "severity": f.severity, "file": f.file, "status": f.status,
                "what_it_means": f.what_it_means, "why_it_matters": f.why_it_matters,
                "fix_prompt": f.fix_prompt,
            }
            for f in scan.findings
        ]
        counts = {s: sum(1 for f in findings if f['severity'] == s) for s in ('critical','high','medium','low')}
        return {
            "scan_id": scan.id, "target": scan.target, "platform": scan.platform,
            "status": scan.status, "summary": counts, "total": len(findings),
            "findings": findings[:50],
        }

def _start_rescan(user_id: str, scan_id: str) -> str:
    with db.SessionLocal() as session:
        scan = (
            session.query(db.Scan)
            .filter(db.Scan.id == scan_id, db.Scan.owner_user_id == user_id)
            .one_or_none()
        )
        if scan is None:
            raise ValueError("Scan not found.")
        if scan.status in ('queued', 'running'):
            raise ValueError("This scan is already running.")
        scan.status = 'queued'
        scan.error = None
        session.add(db.ScanRun(
            scan_id=scan.id, kind='rescan', owner_user_id=user_id, owner_token=scan.owner_token
        ))
        job = jobs.enqueue(session, scan.id, 'rescan')
        session.commit()
    if jobs.inline():
        jobs.submit(job.id)
    return scan.id

async def _wait(user_id: str, scan_id: str, timeout_seconds: float = 180) -> dict:
    deadline = anyio.current_time() + timeout_seconds
    while anyio.current_time() < deadline:
        result = await anyio.to_thread.run_sync(_status, user_id, scan_id)
        if result['status'] not in ('queued', 'running'):
            return result
        await anyio.sleep(1.5)
    return await anyio.to_thread.run_sync(_status, user_id, scan_id)

class APIKeyMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        raw = next(
            (value.decode('utf-8') for name, value in scope.get('headers', []) if name.lower() == b'x-api-key'),
            None,
        )
        try:
            context = await anyio.to_thread.run_sync(api_keys.authenticate_header, raw)
        except Exception as exc:
            status = getattr(exc, 'status_code', 401)
            message = getattr(exc, 'detail', 'MCP authentication failed.')
            body = str(message).encode('utf-8')
            await send({'type': 'http.response.start', 'status': status, 'headers': [
                (b'content-type', b'text/plain; charset=utf-8'),
                (b'content-length', str(len(body)).encode()),
            ]})
            await send({'type': 'http.response.body', 'body': body})
            return
        token = api_keys.set_api_key_context(context)
        try:
            return await self.app(scope, receive, send)
        finally:
            api_keys.reset_api_key_context(token)

@mcp.tool()
async def scan_repository(repo_url: str, wait_for_completion: bool = True) -> dict:
    """Queue a repository scan for the authenticated account."""
    context = api_keys.get_current_api_key_context()
    scan_id = await anyio.to_thread.run_sync(_enqueue, context.user_id, repo_url, 'scan')
    if wait_for_completion:
        status = await _wait(context.user_id, scan_id)
        if status['status'] not in ('queued', 'running'):
            return await anyio.to_thread.run_sync(_findings, context.user_id, scan_id)
        return {**status, 'message': 'Still running; call get_scan_status then get_findings.'}
    return await anyio.to_thread.run_sync(_status, context.user_id, scan_id)

@mcp.tool()
async def scan_live_url(url: str, wait_for_completion: bool = True) -> dict:
    """Queue a passive live URL scan for the authenticated account."""
    context = api_keys.get_current_api_key_context()
    scan_id = await anyio.to_thread.run_sync(_enqueue, context.user_id, url, 'scan')
    if wait_for_completion:
        status = await _wait(context.user_id, scan_id)
        if status['status'] not in ('queued', 'running'):
            return await anyio.to_thread.run_sync(_findings, context.user_id, scan_id)
        return {**status, 'message': 'Still running; call get_scan_status then get_findings.'}
    return await anyio.to_thread.run_sync(_status, context.user_id, scan_id)

@mcp.tool()
async def get_scan_status(scan_id: str) -> dict:
    """Get status for one scan owned by the API-key account."""
    context = api_keys.get_current_api_key_context()
    return await anyio.to_thread.run_sync(_status, context.user_id, scan_id)

@mcp.tool()
async def get_findings(scan_id: str) -> dict:
    """Return findings and fix prompts for one owned scan."""
    context = api_keys.get_current_api_key_context()
    return await anyio.to_thread.run_sync(_findings, context.user_id, scan_id)

@mcp.tool()
async def rescan(scan_id: str, wait_for_completion: bool = True) -> dict:
    """Re-run one owned scan and return the refreshed findings."""
    context = api_keys.get_current_api_key_context()
    await anyio.to_thread.run_sync(_start_rescan, context.user_id, scan_id)
    if wait_for_completion:
        status = await _wait(context.user_id, scan_id)
        if status['status'] not in ('queued', 'running'):
            return await anyio.to_thread.run_sync(_findings, context.user_id, scan_id)
        return {**status, 'message': 'Still running; call get_scan_status then get_findings.'}
    return await anyio.to_thread.run_sync(_status, context.user_id, scan_id)

http_app = APIKeyMiddleware(mcp.streamable_http_app())
