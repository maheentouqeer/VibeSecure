"""The shared Gemini model list: order, env override, and skipping failed models."""
import pytest

from agents import gemini_models as gm


@pytest.fixture(autouse=True)
def reset_model_health():
    gm.reset()
    yield
    gm.reset()


def test_defaults_are_current_models_only():
    # gemini-1.5-flash (shut down Nov 2025) and gemini-2.0-flash (shut down Jun 2026) must not return.
    assert "gemini-1.5-flash" not in gm.DEFAULT_MODELS
    assert "gemini-2.0-flash" not in gm.DEFAULT_MODELS
    assert gm.DEFAULT_MODELS[0] == "gemini-3.8-flash"


def test_every_agent_uses_the_shared_list():
    from agents import explainer_agent, fixprompt_agent, triage_agent

    for mod in (explainer_agent, fixprompt_agent, triage_agent):
        assert mod.MODELS is gm.DEFAULT_MODELS


def test_env_override_replaces_the_list(monkeypatch):
    monkeypatch.setenv("GEMINI_MODELS", " model-a , model-b,, ")
    assert gm.configured_models() == ("model-a", "model-b")
    assert gm.usable_models() == ["model-a", "model-b"]


def test_blank_env_override_uses_defaults(monkeypatch):
    monkeypatch.setenv("GEMINI_MODELS", " , ")
    assert gm.configured_models() == gm.DEFAULT_MODELS


@pytest.mark.parametrize(
    "error",
    [
        "404 NOT_FOUND. models/gemini-x is not found for API version v1beta",
        "403 PERMISSION_DENIED",
        "This model is no longer available",
    ],
)
def test_unavailable_model_is_skipped_from_then_on(error):
    first = gm.usable_models()[0]
    gm.report_failure(first, RuntimeError(error))
    assert first not in gm.usable_models()
    assert gm.usable_models()[0] == gm.DEFAULT_MODELS[1]


def test_transient_error_only_pauses_the_model(monkeypatch):
    first = gm.usable_models()[0]
    clock = [1000.0]
    monkeypatch.setattr(gm.time, "monotonic", lambda: clock[0])
    gm.report_failure(first, RuntimeError("429 RESOURCE_EXHAUSTED"))
    assert first not in gm.usable_models()
    clock[0] += gm.COOLDOWN_SECONDS + 1
    assert first in gm.usable_models()


def test_success_clears_a_cooldown():
    first = gm.usable_models()[0]
    gm.report_failure(first, RuntimeError("503 unavailable"))
    gm.report_success(first)
    assert first in gm.usable_models()


def test_all_rate_limited_models_return_empty_for_deterministic_fallback():
    first, *rest = gm.configured_models()
    gm.report_failure(first, RuntimeError("404 not found"))
    for model in rest:
        gm.report_failure(model, RuntimeError("429 rate limited"))
    assert gm.usable_models() == []


def test_all_permanently_unavailable_models_return_empty():
    for model in gm.configured_models():
        gm.report_failure(model, RuntimeError("404 not found"))
    assert gm.usable_models() == []


def test_rate_limited_models_are_not_retried_for_every_finding(monkeypatch):
    """The cost this module exists to remove: one failed call per finding, per agent."""
    import sys
    import types

    from agents import explainer_agent

    calls = []

    class _Models:
        def generate_content(self, model, contents, config=None):
            calls.append(model)
            if model == "gemini-3.8-flash":
                raise RuntimeError("404 NOT_FOUND")
            raise RuntimeError("503 unavailable")

    class _Client:
        def __init__(self, api_key=None):
            self.models = _Models()

    fake_genai = types.SimpleNamespace(Client=_Client, types=types.SimpleNamespace(GenerateContentConfig=lambda **kw: kw))
    google = types.ModuleType("google")
    google.genai = fake_genai
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", fake_genai.types)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    finding = {"category": "hardcoded_secret", "file": "a.ts", "label": "AWS Access Key", "severity": "high"}
    explainer_agent.explain(finding)
    explainer_agent.explain(finding)
    # Once all models have failed, later findings should make no additional
    # network attempts and instead use the deterministic fallback.
    assert calls == list(gm.DEFAULT_MODELS)
