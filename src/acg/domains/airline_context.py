from __future__ import annotations
import re
from collections.abc import Iterable
HEALTH_PATTERNS = ('\\bhealth\\b', '\\bmedical\\b', '\\bsick\\b', '\\bfeeling unwell\\b', '\\bnot feeling well\\b', '\\bnot well\\b')
WEATHER_PATTERNS = ('\\bweather\\b', '\\bstorm\\b', '\\bhurricane\\b')
AIRLINE_CANCEL_PATTERNS = ('\\bairline cancelled\\b', '\\bairline canceled\\b', '\\bflight was cancelled\\b', '\\bflight was canceled\\b')
CHANGE_PLAN_PATTERNS = ('\\bchange of plan\\b', '\\bchanged my plans\\b', '\\bno longer (?:need|want|travel)\\b', '\\bbooked by mistake\\b', '\\bswitch(?:ing)?\\s+(?:to|from)\\b', '\\bupgrade(?:ing)?\\s+(?:to|from)\\b', '\\bdowngrade(?:ing)?\\s+(?:to|from)\\b', '\\brebook(?:ing)?\\b', '\\bbook(?:ing)?\\s+(?:a|another)\\s+(?:new|different)\\b', '\\bdifferent\\s+(?:fare|cabin|flight|itinerary)\\b')
_TIME = '(?P<hour>\\d{1,2})(?::(?P<minute>\\d{2}))?\\s*(?P<ampm>a\\.?m\\.?|p\\.?m\\.?)?'
_CONSTRAINT_PATTERN = re.compile(f'(?P<field>depart(?:ure|ing)?|leave|leaving|arriv(?:e|al|ing)?)[^.!?\\n]{{0,64}}?(?P<relation>before|no later than|by|after|no earlier than)\\s+{_TIME}', re.IGNORECASE)

def _matches(patterns: tuple[str, ...], text: str) -> bool:
    return any((re.search(pattern, text) for pattern in patterns))

def propose_cancellation_reason(user_texts: Iterable[str]) -> str | None:
    text = '\n'.join((str(value) for value in user_texts)).lower()
    if _matches(WEATHER_PATTERNS, text):
        return 'weather'
    if _matches(HEALTH_PATTERNS, text):
        return 'health'
    if _matches(AIRLINE_CANCEL_PATTERNS, text):
        return 'airline_cancelled_flight'
    if _matches(CHANGE_PLAN_PATTERNS, text):
        return 'change_of_plan'
    return None

def _normalize_clock(hour_text: str, minute_text: str | None, ampm: str | None) -> str | None:
    hour = int(hour_text)
    minute = int(minute_text or '0')
    if minute > 59:
        return None
    marker = (ampm or '').lower().replace('.', '')
    if marker:
        if not 1 <= hour <= 12:
            return None
        if marker == 'am':
            hour = 0 if hour == 12 else hour
        elif marker == 'pm':
            hour = 12 if hour == 12 else hour + 12
        else:
            return None
    elif not 0 <= hour <= 23:
        return None
    return f'{hour:02d}:{minute:02d}:00'

def _scope(text: str) -> str:
    lower = text.lower()
    if any((token in lower for token in ('return', 'inbound', 'back flight', 'flight back'))):
        return 'return'
    if any((token in lower for token in ('outbound', 'departing flight', 'first leg'))):
        return 'outbound'
    return 'all'

def propose_time_constraints(user_texts: Iterable[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in user_texts:
        text = str(raw)
        for match in _CONSTRAINT_PATTERN.finditer(text):
            threshold = _normalize_clock(match.group('hour'), match.group('minute'), match.group('ampm'))
            if threshold is None:
                continue
            field = 'arrival_time' if match.group('field').lower().startswith('arriv') else 'departure_time'
            comparator = {'before': 'lt', 'no later than': 'le', 'by': 'le', 'after': 'gt', 'no earlier than': 'ge'}[match.group('relation').lower()]
            scope = _scope(text)
            key = (field, comparator, threshold, scope)
            if key in seen:
                continue
            seen.add(key)
            rows.append({'field': field, 'comparator': comparator, 'threshold': threshold, 'scope': scope, 'source_excerpt': text.strip()[:200]})
    return rows
__all__ = ['propose_cancellation_reason', 'propose_time_constraints']
