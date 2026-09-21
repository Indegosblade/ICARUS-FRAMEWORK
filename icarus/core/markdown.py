"""Safe rendering helpers for Markdown output derived from database values."""

import re
from typing import Any

# C0/C1 control characters: 0x00-0x1F, DEL (0x7F), and 0x80-0x9F.  ESC is
# included, so ANSI terminal sequences cannot survive into rendered output.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_markdown(value: Any) -> str:
    """Render an untrusted value as readable, inert Markdown text.

    Literal backslashes are escaped first. Structural Markdown characters and
    every C0/C1 control are then made visible, preserving the underlying data
    without allowing it to alter the surrounding report or terminal output.
    """
    text = "null" if value is None else str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("`", "\\x60")
    text = text.replace("|", "\\|")
    return _CONTROL_RE.sub(lambda match: f"\\x{ord(match.group()):02x}", text)
