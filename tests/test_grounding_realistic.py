"""The grounding guard against realistic model output, not hand-picked sentences.

Every false rejection found in review (env-var names, config files, `res.json()`,
a second secret on the same line) was invisible to short invented test strings.
These cases are written the way Gemini actually phrases fixes. "Good" answers must
pass; answers that invent a file, a table or a line must fail. Both go through the
same masking the agents use, so the placeholders the model really sees are covered.
"""
import pytest

from agents.evidence_guard import validate_evidence_grounding
from agents.privacy import Masker

SECRET = {"category": "hardcoded_secret", "file": "src/config/aws.ts", "line": 12, "label": "AWS Access Key"}
HEADER = {"category": "missing_header", "file": "https://myapp.vercel.app", "label": "Content-Security-Policy"}
CORS = {"category": "cors_misconfig", "file": "https://myapp.vercel.app", "label": "CORS allows any origin (*)"}
EXPOSED = {"category": "exposed_file", "file": ".env", "label": "Exposed .env file"}
RLS = {"category": "missing_access_control", "file": "supabase/migrations/001_init.sql", "table": "profiles",
       "label": "Row Level Security disabled on profiles"}

GOOD = [
    (SECRET, "A live AWS access key is hardcoded on line 12 of src/config/aws.ts. Anyone who can read your repository can use it."),
    (SECRET, "Move the key into `process.env.AWS_ACCESS_KEY_ID`, rotate it in the AWS console, and add `.env` to `.gitignore`."),
    (SECRET, "Add `AWS_ACCESS_KEY_ID=your-key` to your .env file and read it on the server only."),
    (SECRET, "Remove the `NEXT_PUBLIC_` prefix so the value is never bundled into browser code."),
    (SECRET, "Read the value on the server, then return it with `await res.json()` only after checking the session."),
    (SECRET, "Never use `import.meta.env.VITE_AWS_KEY` for secrets; Vite exposes every VITE_ variable to the browser."),
    (HEADER, "Add a Content-Security-Policy header in `next.config.js`, or in `vercel.json` under headers, or in `middleware.ts`."),
    (HEADER, "On Netlify, put the header in `netlify.toml`; on Vite use `vite.config.ts` with a server plugin."),
    (CORS, "Replace the wildcard with your real domain in the `Access-Control-Allow-Origin` header and stop reflecting any origin."),
    (EXPOSED, "Delete `.env` from the deployed `public/` folder, add it to `.gitignore`, then rotate every key it held."),
    (RLS, "Run `ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;` then `CREATE POLICY \"own rows\" ON profiles USING (auth.uid() = user_id);`"),
    (RLS, "Row Level Security is off for table profiles, so anyone with your anon key can read every row."),
]

BAD = [
    (SECRET, "Also check `src/lib/other.ts`, which probably has the same key."),
    (SECRET, "The key is defined on line 99 of src/config/aws.ts."),
    (SECRET, "Edit server/index.ts and move the key out of that file."),
    (RLS, "Run `ALTER TABLE users ENABLE ROW LEVEL SECURITY;` to protect your data."),
    (RLS, "Enable RLS on table accounts and add a policy using auth.uid()."),
]


def _masked(finding, text):
    """Validate the way the agents do: masked finding + masked text, original file/table alongside."""
    masker = Masker()
    safe = masker.mask_finding(dict(finding))
    safe_text = masker.mask_text(text) if hasattr(masker, "mask_text") else text
    return {
        **safe,
        "_original_file": finding.get("file", ""),
        "_original_table": finding.get("table", ""),
    }, safe_text


@pytest.mark.parametrize("finding,text", GOOD)
def test_realistic_good_answers_pass(finding, text):
    ok, reason = validate_evidence_grounding(text, finding)
    assert ok, f"false rejection: {reason} | {text}"


@pytest.mark.parametrize("finding,text", GOOD)
def test_realistic_good_answers_pass_through_masking(finding, text):
    masked_finding, masked_text = _masked(finding, text)
    ok, reason = validate_evidence_grounding(masked_text, masked_finding)
    assert ok, f"false rejection after masking: {reason} | {text}"


@pytest.mark.parametrize("finding,text", BAD)
def test_invented_specifics_are_rejected(finding, text):
    ok, _ = validate_evidence_grounding(text, finding)
    assert not ok, f"invented detail slipped through: {text}"
