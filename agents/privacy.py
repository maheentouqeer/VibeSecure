"""Masks sensitive values before text reaches an LLM, and restores them after.

The promise this module backs: **secret values never leave the scanner, and
project-identifying names never reach the model provider.** Before any
finding is sent to Gemini:

  * secret material is removed (no characters of a detected secret are sent),
  * file paths, database table names and scanned URLs are replaced by stable
    placeholders such as <FILE_1.ts>, <TABLE_2> and <URL_3>,
  * anything in free text that looks like a credential, token, email address or
    IP address is redacted.

The model reasons about the placeholders and writes its answer with them; the
answer is then put back together locally (restore()), so users still read
"fix src/config/aws.ts", never "fix <FILE_1.ts>". A placeholder the model
invents, or one we cannot resolve, makes the whole answer unusable
(unresolved()), and the caller falls back to its deterministic template
instead of showing a broken or leaked value.

A file's extension stays visible (<FILE_1.ts>) because the model needs to know
the language to give useful advice. Deterministic within one Masker: the same
value always gets the same placeholder.

What is still sent: the category and label of the issue (for example
"Stripe Secret Key" or "Row-Level Security not enabled"), severity, the
platform name, line numbers, and rule text, all with the masking above applied.
"""
import re

from scanner.secrets_scanner import PATTERNS as _SECRET_PATTERNS

# Generic, non-identifying file names the model benefits from seeing as they are.
_WELL_KNOWN = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.example", ".gitignore",
    ".git/config", "package.json", "package-lock.json", "requirements.txt", "docker-compose.yml",
    "dockerfile", "next.config.js", "next.config.ts", "vite.config.ts", "vite.config.js", "tsconfig.json",
}
_CODE_EXT = r"(?:tsx?|jsx?|mjs|cjs|py|rb|go|rs|java|kt|php|cs|sql|json|ya?ml|toml|env|ini|cfg|conf|md|html?|css|scss|vue|svelte|sh)"
_LOOKS_LIKE_FILE = re.compile(rf"\.{_CODE_EXT}$", re.IGNORECASE)
_PATH_IN_TEXT = re.compile(
    rf"(?<![\w/.@-])((?:[\w.@-]+/)+[\w.@-]+\.{_CODE_EXT}|[\w-]+\.{_CODE_EXT})(?![\w/-])", re.IGNORECASE
)
_NOT_FILES = {"node.js", "next.js", "vue.js", "react.js", "express.js", "nuxt.js", "three.js", "d3.js", "chart.js"}

_REDACTIONS = (
    re.compile(r"eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{5,}"),  # JWTs
    re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),  # email addresses
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # IPv4 addresses
    re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}(?![\w])"),  # long hex / base64 / token-like runs
)
_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>)\]},]+", re.IGNORECASE)
_REDACTED = "[redacted]"
_SECRET_HIDDEN = "[secret value hidden]"

_BRACKETED = re.compile(r"[<\[{]{1,2}\s*(FILE|TABLE|URL)_(\d+)(?:\.[A-Za-z0-9]{1,8})?\s*[>\]}]{1,2}")
_BARE = re.compile(r"\b(FILE|TABLE|URL)_(\d+)(?:\.[A-Za-z0-9]{1,8})?\b")
_PLACEHOLDER_LIKE = re.compile(r"(?:FILE|TABLE|URL)_\d+(?:\.[A-Za-z0-9]{1,8})?")

# Deliberately no concrete example (like <FILE_1.ts>): a model that copies an example into its
# answer would name a placeholder that does not exist for this finding.
PLACEHOLDER_NOTE = (
    "Some real names are hidden behind placeholders: a file appears as <FILE_n.ext>, a database table as "
    "<TABLE_n> and a web address as <URL_n>, where n is a number. Use only the placeholders that appear in "
    "the finding below, exactly as written, and never guess what they stand for."
)


def _extension(value: str) -> str:
    match = re.search(r"\.([A-Za-z0-9]{1,8})$", value)
    return "." + match.group(1).lower() if match else ""


class Masker:
    def __init__(self) -> None:
        self._by_value: dict[tuple[str, str], str] = {}  # (kind, value) -> "FILE_1"
        self._by_key: dict[str, str] = {}  # "FILE_1" -> original value
        self._counts: dict[str, int] = {}

    # ------------------------------------------------------------ placeholders

    def _placeholder(self, kind: str, value: str, ext: str = "") -> str:
        key = self._by_value.get((kind, value))
        if key is None:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            key = f"{kind}_{self._counts[kind]}"
            self._by_value[(kind, value)] = key
            self._by_key[key] = value
        return f"<{key}{ext}>"

    @staticmethod
    def _is_sensitive_path(value: str) -> bool:
        stripped = value.strip()
        if not stripped or stripped.lower() in _WELL_KNOWN or stripped.lower() in _NOT_FILES:
            return False
        return "/" in stripped or "\\" in stripped or bool(_LOOKS_LIKE_FILE.search(stripped))

    def mask_path(self, value: str) -> str:
        return self._placeholder("FILE", value, _extension(value)) if self._is_sensitive_path(value) else value

    def mask_url(self, value: str) -> str:
        return self._placeholder("URL", value)

    def mask_table(self, value: str) -> str:
        return self._placeholder("TABLE", value) if value else value

    def mask_file_field(self, value: str) -> str:
        if value.lower().startswith(("http://", "https://")):
            return self.mask_url(value)
        return self.mask_path(value)

    # -------------------------------------------------------------------- text

    def mask_text(self, text: str) -> str:
        """Masks known values, path-like tokens and credential-like strings in free text."""
        if not text:
            return text
        # 1. values we already know, longest first so a path is not partly replaced by a shorter one
        known = sorted(self._by_value.items(), key=lambda kv: len(kv[0][1]), reverse=True)
        for (kind, value), key in known:
            if value and value in text:
                ext = _extension(value) if kind == "FILE" else ""
                text = text.replace(value, f"<{key}{ext}>")
        # 2. any other URL in prose, before the credential patterns so a secret inside a URL goes with it
        def mask_url_mention(match: re.Match) -> str:
            url = match.group(0)
            trailing = ""
            while url and url[-1] in ".;:!?":
                trailing, url = url[-1] + trailing, url[:-1]
            return self.mask_url(url) + trailing

        text = _URL_IN_TEXT.sub(mask_url_mention, text)
        # 3. credentials, tokens, emails, IP addresses (one-way)
        for pattern in _SECRET_PATTERNS.values():
            text = re.sub(pattern, _REDACTED, text)
        for pattern in _REDACTIONS:
            text = pattern.sub(_REDACTED, text)
        # 4. other file paths mentioned in prose (reversible). A placeholder such as FILE_1.ts
        #    looks like a file name too, so it must be skipped or it would be masked twice.
        def mask_mentioned(match: re.Match) -> str:
            token = match.group(1)
            return token if _PLACEHOLDER_LIKE.fullmatch(token) else self.mask_path(token)

        return _PATH_IN_TEXT.sub(mask_mentioned, text)

    # ---------------------------------------------------------------- findings

    def mask_finding(self, finding: dict) -> dict:
        """A copy of `finding` that is safe to send to the model."""
        safe: dict = {}
        # Register the structured values first, so prose that repeats them is masked consistently.
        masked_file = self.mask_file_field(str(finding["file"])) if isinstance(finding.get("file"), str) else None
        masked_table = self.mask_table(finding["table"]) if isinstance(finding.get("table"), str) else None

        for key, value in finding.items():
            if key == "file" and masked_file is not None:
                safe[key] = masked_file
            elif key == "table" and masked_table is not None:
                safe[key] = masked_table
            elif key == "match_preview":
                safe[key] = _SECRET_HIDDEN  # not even the first characters of a secret are sent
            elif isinstance(value, str):
                safe[key] = self.mask_text(value)
            else:
                safe[key] = value
        return safe

    # ----------------------------------------------------------------- restore

    def restore(self, text: str) -> str:
        """Puts the real names back into text the model wrote."""
        if not text:
            return text

        def swap(match: re.Match) -> str:
            return self._by_key.get(f"{match.group(1)}_{match.group(2)}", match.group(0))

        return _BARE.sub(swap, _BRACKETED.sub(swap, text))

    def unresolved(self, text: str) -> list[str]:
        """Placeholders still in `text` after restore(): ones the model made up, or mangled."""
        return [m.group(0) for m in _BRACKETED.finditer(self.restore(text))]

    def restore_finding(self, finding: dict) -> dict:
        return {k: self.restore(v) if isinstance(v, str) else v for k, v in finding.items()}
