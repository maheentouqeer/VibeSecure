"""Renders the public "Secure-VibeCode" SVG badge (shields.io style).

The badge is unauthenticated, so it deliberately reveals only whether the
scan is verified -- never finding counts, severities, or the target.
"""
from xml.sax.saxutils import escape

LABEL = "secure-vibecode"
GREEN = "#22c55e"
GREY = "#94a3b8"
LABEL_BG = "#334155"
CHAR_WIDTH = 6.6
PADDING = 10


def _width(text: str) -> int:
    return int(len(text) * CHAR_WIDTH) + PADDING * 2


def render_badge(message: str, verified: bool) -> str:
    left_w, right_w = _width(LABEL), _width(message)
    total = left_w + right_w
    color = GREEN if verified else GREY
    label, msg = escape(LABEL), escape(message)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" '
        f'aria-label="{label}: {msg}">'
        f"<title>{label}: {msg}</title>"
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{left_w}" height="20" fill="{LABEL_BG}"/>'
        f'<rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>'
        f"</g>"
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{left_w / 2}" y="14">{label}</text>'
        f'<text x="{left_w + right_w / 2}" y="14">{msg}</text>'
        f"</g></svg>"
    )
