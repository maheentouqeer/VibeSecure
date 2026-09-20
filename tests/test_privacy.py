"""Nothing sensitive may reach the model provider, and users must still get real names back.

A fake Gemini records every prompt it is sent. Realistic sensitive data goes in;
the assertions are on what actually left the process."""
import json
import logging
import os
import random
import re
import string
from unittest import mock

import pytest

from agents.explainer_agent import explain
from agents.fixprompt_agent import generate_fix_prompt
from agents.privacy import Masker
from agents.triage_agent import triage
from orchestrator import enrich

PATH = "src/billing/acme-corp-stripe.ts"
PATH2 = "supabase/migrations/20240101_patients.sql"
TABLE = "patients_records"
URL = "https://acme-secret-portal.example.com/admin/dashboard"
EMAIL = "cto@acme-corp.example"
AWS = "AKIAIOSFODNN7EXAMPLE"
STRIPE = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
IP = "10.20.30.40"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY21lLWNvcnAifQ.c2lnbmF0dXJlLXZhbHVl"
HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

# Every one of these must be absent from anything sent to the model.
FORBIDDEN = [PATH, PATH2, TABLE, URL, "acme-corp", "acme-secret", "patients", EMAIL, AWS, STRIPE, IP, JWT, HEX, "AKIA12", "sk_liv"]

PLACEHOLDER = re.compile(r"<(?:FILE|TABLE|URL)_\d+(?:\.\w+)?>")


def _findings():
    return [
        {"category": "hardcoded_secret", "label": "Stripe Secret Key", "file": PATH,
         "match_preview": "sk_liv...(masked)", "raw_severity": "critical", "line": 12,
         "message": f"Key found in {PATH}; owner {EMAIL} at {IP}; token {STRIPE} seen with {AWS}"},
        {"category": "missing_access_control", "label": "Row-Level Security not enabled", "file": "supabase migrations",
         "table": TABLE, "raw_severity": "critical", "message": f"Table {TABLE} defined in {PATH2}"},
        {"category": "exposed_file", "label": "Exposed .env file", "file": ".env", "raw_severity": "critical",
         "message": f"served from {URL} with jwt {JWT} and hash {HEX}"},
        {"category": "missing_header", "label": "Missing Content-Security-Policy header", "file": URL, "raw_severity": "medium"},
    ]


class FakeGemini:
    """Records every prompt; answers using the placeholders it was given, like a real model would."""

    def __init__(self, answer=None):
        self.prompts: list[str] = []
        self.answer = answer

    def generate(self, model=None, contents=None, config=None):
        self.prompts.append(contents)
        text = self.answer(contents) if self.answer else self.default(contents)
        return mock.MagicMock(text=text)

    @staticmethod
    def default(prompt):
        held = PLACEHOLDER.findall(prompt)
        files = [p for p in held if p.startswith("<FILE_")]
        tables = [p for p in held if p.startswith("<TABLE_")]
        where = files[0] if files else "the affected file"
        if "triage expert" in prompt:
            masked = json.loads(re.search(r"(\[\s*\{.*\}\s*\])", prompt, re.DOTALL).group(1))
            out = []
            for i, f in enumerate(masked):
                item = {"id": f"f{i}", "category": f["category"], "label": f["label"], "file": f["file"], "severity": "high"}
                if "table" in f:
                    item["table"] = f["table"]
                out.append(item)
            return json.dumps(out)
        if "cybersecurity expert" in prompt:
            return json.dumps({
                "what_it_means": f"A problem was found in {where}.",
                "why_it_matters": f"Anyone reading {where} can abuse it." + (f" Affects {tables[0]}." if tables else ""),
            })
        return f"In {where}, move the secret to an environment variable." + (f" Then lock down {tables[0]}." if tables else "")


@pytest.fixture()
def gemini(monkeypatch):
    def install(fake: FakeGemini):
        client = mock.MagicMock()
        client.models.generate_content.side_effect = fake.generate
        genai = mock.MagicMock()
        genai.Client.return_value = client
        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        ctx = mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=genai), "google.genai": genai})
        ctx.start()
        return fake

    installed = []
    yield lambda fake=None: installed.append(ctx := install(fake or FakeGemini())) or ctx
    mock.patch.stopall()


def _assert_clean(prompts):
    assert prompts, "the model was never called, so nothing was tested"
    for prompt in prompts:
        for value in FORBIDDEN:
            assert value not in prompt, f"{value!r} was sent to the model:\n{prompt}"


# ============================ what actually gets sent =======================


def test_explainer_never_sends_names_paths_or_secrets(gemini):
    fake = gemini()
    for finding in _findings():
        explain(finding)
    _assert_clean(fake.prompts)


def test_fix_prompt_agent_never_sends_them_either(gemini):
    fake = gemini()
    for finding in _findings():
        generate_fix_prompt(finding, "lovable_supabase")
    _assert_clean(fake.prompts)


def test_triage_never_sends_them(gemini):
    fake = gemini()
    triage(_findings())
    _assert_clean(fake.prompts)


def test_the_whole_pipeline_leaks_nothing_and_still_reads_naturally(gemini):
    fake = gemini()
    results = enrich(_findings(), "lovable_supabase")

    _assert_clean(fake.prompts)
    assert len(fake.prompts) >= 1 + 2 * 4  # triage + explain + fix prompt per finding
    by_label = {r["label"]: r for r in results}
    stripe = by_label["Stripe Secret Key"]
    assert stripe["file"] == PATH  # the real path is back
    assert PATH in stripe["what_it_means"] and PATH in stripe["fix_prompt"]
    rls = by_label["Row-Level Security not enabled"]
    assert rls["table"] == TABLE and TABLE in rls["why_it_matters"]
    for r in results:
        for field in ("what_it_means", "why_it_matters", "fix_prompt"):
            assert not PLACEHOLDER.search(r[field]), f"placeholder shown to the user: {r[field]}"


def test_the_model_is_told_what_the_placeholders_are(gemini):
    fake = gemini()
    explain(_findings()[0])
    assert "placeholders" in fake.prompts[0] and "<FILE_1.ts>" in fake.prompts[0]


def test_what_the_model_legitimately_needs_is_still_sent(gemini):
    fake = gemini()
    explain(_findings()[0])
    prompt = fake.prompts[0]
    for needed in ("hardcoded_secret", "Stripe Secret Key", '"line": 12', ".ts>"):
        assert needed in prompt


def test_generic_names_stay_readable(gemini):
    fake = gemini()
    explain(_findings()[2])  # file ".env"
    generate_fix_prompt(_findings()[1], "lovable_supabase")  # file "supabase migrations"
    joined = "\n".join(fake.prompts)
    assert '"file": ".env"' in joined and '"file": "supabase migrations"' in joined


def test_secret_material_is_dropped_completely(gemini):
    fake = gemini()
    explain(_findings()[0])
    assert "[secret value hidden]" in fake.prompts[0]
    assert "sk_liv" not in fake.prompts[0] and "masked" not in fake.prompts[0].replace("[secret value hidden]", "")


# ================================ bad model output ==========================


def test_a_placeholder_the_model_invents_falls_back_to_the_template(gemini):
    fake = gemini(FakeGemini(answer=lambda p: json.dumps(
        {"what_it_means": "See <FILE_99.ts> for details.", "why_it_matters": "Bad."})))
    result = explain(_findings()[0])
    assert "<FILE_" not in json.dumps(result)
    assert result["what_it_means"] == "A secret or API key is hardcoded directly in your code."  # the template
    assert len(fake.prompts) == 2  # it tried both models before giving up


def test_an_invented_placeholder_in_a_fix_prompt_never_reaches_the_user(gemini):
    gemini(FakeGemini(answer=lambda p: "Edit <FILE_7.py> and <TABLE_3> now."))
    out = generate_fix_prompt(_findings()[0], "generic")
    assert "<FILE_" not in out and "<TABLE_" not in out and PATH in out  # deterministic template, real path


def test_a_hallucinated_placeholder_in_triage_falls_back_to_the_deterministic_result(gemini):
    gemini(FakeGemini(answer=lambda p: json.dumps(
        [{"id": "x", "category": "c", "label": "l", "file": "<FILE_42.ts>", "severity": "low"}])))
    out = triage(_findings())
    assert len(out) == len(_findings()) and all("<FILE_" not in f["file"] for f in out)
    assert {f["file"] for f in out} >= {PATH, ".env"}


@pytest.mark.parametrize("written", ["FILE_1.ts", "{{FILE_1.ts}}", "[FILE_1.ts]", "< FILE_1.ts >", "<FILE_1>"])
def test_slightly_mangled_placeholders_are_still_restored(gemini, written):
    gemini(FakeGemini(answer=lambda p: json.dumps({"what_it_means": f"Look at {written}.", "why_it_matters": "x"})))
    assert explain(_findings()[0])["what_it_means"] == f"Look at {PATH}."


def test_a_wrong_model_answer_does_not_leak_into_logs(gemini, caplog):
    gemini(FakeGemini(answer=lambda p: json.dumps({"what_it_means": "<FILE_99.ts>", "why_it_matters": "x"})))
    with caplog.at_level(logging.DEBUG):
        explain(_findings()[0])
    for value in FORBIDDEN:
        assert value not in caplog.text


# ================================== the masker ==============================


def test_placeholders_are_stable_within_one_masker_and_keep_the_extension():
    m = Masker()
    assert m.mask_path(PATH) == "<FILE_1.ts>"
    assert m.mask_path(PATH) == "<FILE_1.ts>"
    assert m.mask_path(PATH2) == "<FILE_2.sql>"
    assert m.mask_table(TABLE) == "<TABLE_1>" and m.mask_url(URL) == "<URL_1>"


def test_the_same_path_mentioned_in_prose_gets_the_same_placeholder():
    m = Masker()
    safe = m.mask_finding({"file": PATH, "message": f"problem in {PATH} and again {PATH}"})
    assert safe["message"] == "problem in <FILE_1.ts> and again <FILE_1.ts>"
    assert "<<" not in safe["message"]  # a placeholder is never masked a second time


def test_paths_only_mentioned_in_prose_are_masked_and_restorable():
    m = Masker()
    masked = m.mask_text("see lib/secret-module/auth.py and also config.yaml")
    assert "secret-module" not in masked and "config.yaml" not in masked
    assert m.restore(masked) == "see lib/secret-module/auth.py and also config.yaml"


def test_framework_names_that_look_like_files_are_left_alone():
    assert Masker().mask_text("uses Node.js, Next.js and Vue.js") == "uses Node.js, Next.js and Vue.js"


@pytest.mark.parametrize("secret", [AWS, STRIPE, JWT, HEX, EMAIL, IP, "ghp_" + "a" * 36, "AIza" + "b" * 35])
def test_credential_like_strings_in_prose_are_redacted_one_way(secret):
    m = Masker()
    out = m.mask_text(f"found {secret} in the config")
    assert secret not in out and "[redacted]" in out
    assert secret not in m.restore(out)  # they cannot be brought back, by design


def test_restore_only_touches_real_placeholders():
    m = Masker()
    m.mask_path(PATH)
    text = "Keep FILE_ONE, TABLE_X, PROFILE_1.ts and <FILE_1.ts>."
    assert m.restore(text) == f"Keep FILE_ONE, TABLE_X, PROFILE_1.ts and {PATH}."


def test_unresolved_reports_only_unknown_bracketed_placeholders():
    m = Masker()
    m.mask_path(PATH)
    assert m.unresolved("<FILE_1.ts> is fine") == []
    assert m.unresolved("but <FILE_5.ts> and <TABLE_1> are invented") == ["<FILE_5.ts>", "<TABLE_1>"]


def test_masking_does_not_change_the_callers_finding():
    original = _findings()[0]
    snapshot = json.loads(json.dumps(original))
    Masker().mask_finding(original)
    assert original == snapshot


def test_non_string_values_pass_through():
    safe = Masker().mask_finding({"file": PATH, "line": 42, "tags": ["a"], "count": None})
    assert safe["line"] == 42 and safe["tags"] == ["a"] and safe["count"] is None


# ================================== fuzzing =================================


def _word(rng, n=None):
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n or rng.randint(6, 12)))


def test_random_findings_never_leak_their_names(gemini):
    rng = random.Random(1234)
    fake = gemini()
    secrets_seen = []

    for _ in range(120):
        directory = "/".join(_word(rng) for _ in range(rng.randint(1, 3)))
        path = f"{directory}/{_word(rng)}.{rng.choice(['ts', 'py', 'sql', 'js', 'tsx', 'json'])}"
        table = "tbl_" + _word(rng)
        host = _word(rng, 10) + ".example.com"
        secret = "sk_live_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(28))
        finding = {
            "category": "hardcoded_secret", "label": "Stripe Secret Key", "file": path, "table": table,
            "match_preview": secret[:6] + "...(masked)",
            "message": f"in {path} for {table} on https://{host}/x with {secret}",
            "raw_severity": "critical",
        }
        secrets_seen.append((path, table, host, secret, directory))
        explain(finding)
        generate_fix_prompt(finding, "generic")

    sent = "\n".join(fake.prompts)
    assert len(fake.prompts) == 240
    for path, table, host, secret, directory in secrets_seen:
        for value in (path, table, host, secret, directory, secret[:8]):
            assert value not in sent, f"{value!r} leaked"


def test_round_trip_restores_random_paths_and_tables_exactly():
    rng = random.Random(99)
    for _ in range(200):
        m = Masker()
        path = "/".join(_word(rng) for _ in range(rng.randint(1, 4))) + "." + rng.choice(["ts", "py", "sql", "md"])
        table = _word(rng)
        safe = m.mask_finding({"file": path, "table": table})
        restored = m.restore_finding(safe)
        assert restored == {"file": path, "table": table}
        assert path not in json.dumps(safe) and table not in json.dumps(safe)


def test_the_instruction_note_contains_no_placeholder_a_model_could_copy():
    """A real model that copies an example placeholder into its answer names one that
    does not exist for this finding (which is rejected, degrading to a template)."""
    from agents.privacy import PLACEHOLDER_NOTE

    assert PLACEHOLDER.findall(PLACEHOLDER_NOTE) == []
    assert Masker().unresolved(PLACEHOLDER_NOTE) == []
