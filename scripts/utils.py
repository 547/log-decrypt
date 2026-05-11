"""
Shared utilities for log-decrypt.
"""
import json
from typing import Any


def json_fmt(obj: Any) -> str:
    """
    Format any object as a pretty-printed JSON string.
    Convenience wrapper over json.dumps(ensure_ascii=False, indent=2).
    """
    return json.dumps(obj, ensure_ascii=False, indent=2)
