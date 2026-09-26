from __future__ import annotations
from pathlib import Path

def is_mutating_tool(tool) -> bool:
    function = getattr(tool, '_func', None)
    legacy = getattr(function, '__mutates_state__', None)
    if legacy is not None:
        return bool(legacy)
    tool_type = getattr(function, '__tool_type__', None)
    value = getattr(tool_type, 'value', tool_type)
    if value is not None:
        return str(value).lower() == 'write'
    info = getattr(tool, 'info', None)
    if isinstance(info, dict) and 'mutates_state' in info:
        return bool(info['mutates_state'])
    return False
__all__ = ['is_mutating_tool']
