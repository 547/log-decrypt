"""
Shared utilities for log-decrypt.
"""
import json
from typing import Any, Optional, Tuple


def json_load(f) -> Tuple[Any, Optional[Exception]]:
    """
    Load JSON from a file object. Returns (parsed, None) on success, (None, error) on failure.
    """
    try:
        return json.load(f), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, e


def json_parse(text: str) -> Tuple[Optional[Any], Optional[Exception]]:
    """
    Parse text as JSON. Returns (parsed, None) on success, (None, error) on failure.
    """
    try:
        return json.loads(text), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, e


def json_fmt(obj: Any) -> str:
    """
    Format any object as a pretty-printed JSON string.
    Handles both serializable objects (dict/list/etc.) and JSON string input.
    """
    if isinstance(obj, str):
        parsed, _ = json_parse(obj)
        if parsed is not None:
            return json.dumps(parsed, ensure_ascii=False, indent=2)
        return obj
    return json.dumps(obj, ensure_ascii=False, indent=2)


def json_try_fmt(text: str) -> str:
    """
    Try to parse text as JSON and format it with indentation.
    If parsing fails, return the original text unchanged.
    """
    parsed, _ = json_parse(text)
    if parsed is not None:
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    return text
