"""Pydantic models for request/response validation.

`Finding` mirrors the shared contract exactly — every field the
orchestrator/agents produce, with `status` restricted to open/resolved.
"""
from datetime import datetime
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["critical", "high", "medium", "low"]
FindingStatus = Literal["open", "resolved"]


class ScanCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, description="GitHub repo URL or live deployed app URL")

    @field_validator("target")
    @classmethod
    def target_must_be_a_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "target must be a valid http(s) URL, e.g. "
                "https://github.com/org/repo or https://my-app.example.com"
            )
        return value


class Finding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    category: str
    label: str
    file: str
    severity: Severity
    what_it_means: str
    why_it_matters: str
    fix_prompt: str
    status: FindingStatus


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    platform: str
    status: str
    created_at: datetime
    findings: list[Finding] = []


class BadgeResponse(BaseModel):
    scan_id: str
    passed: bool
    open_critical: int
    open_high: int
    reason: str


class ErrorResponse(BaseModel):
    detail: str
