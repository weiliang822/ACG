from __future__ import annotations
import copy
import datetime as dt
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping
NOW = dt.datetime.fromisoformat('2024-05-15T15:00:00')

@dataclass(frozen=True)
class ProjectionResult:
    fields: dict[str, Any]
    missing_witnesses: tuple[str, ...]
    ambiguous_witnesses: tuple[str, ...]

def _flight_record(db: Mapping[str, Any], requested: Mapping[str, Any]) -> dict[str, Any] | None:
    number = str(requested.get('flight_number', ''))
    date_value = str(requested.get('date', ''))
    flight = db.get('flights', {}).get(number)
    if not isinstance(flight, Mapping):
        return None
    dated = flight.get('dates', {}).get(date_value)
    if not isinstance(dated, Mapping):
        return None
    return {'flight_number': number, 'date': date_value, 'origin': flight.get('origin'), 'destination': flight.get('destination'), **{key: flight[key] for key in ('scheduled_departure_time_est', 'scheduled_arrival_time_est') if key in flight}, **copy.deepcopy(dict(dated))}

def _resolved_flights(db: Mapping[str, Any], requested: list[Mapping[str, Any]]) -> list[dict[str, Any]] | None:
    output = []
    for row in requested:
        resolved = _flight_record(db, row)
        if resolved is None:
            return None
        output.append(resolved)
    return output

def _route_consistent(rows: list[Mapping[str, Any]], origin: str, destination: str, flight_type: str) -> bool:
    if not rows or rows[0].get('origin') != origin:
        return False
    if any((left.get('destination') != right.get('origin') for left, right in zip(rows, rows[1:]))):
        return False
    if flight_type == 'one_way':
        return rows[-1].get('destination') == destination
    if flight_type != 'round_trip' or rows[-1].get('destination') != origin:
        return False
    return any((row.get('destination') == destination for row in rows))

def _free_baggage_allowance(membership: str, cabin: str, passengers: int) -> int | None:
    member_offset = {'regular': 0, 'silver': 1, 'gold': 2}.get(membership)
    cabin_offset = {'basic_economy': 0, 'economy': 1, 'business': 2}.get(cabin)
    if member_offset is None or cabin_offset is None or passengers < 1:
        return None
    return (member_offset + cabin_offset) * passengers

def _status_for_segment(db: Mapping[str, Any], segment: Mapping[str, Any]) -> str | None:
    resolved = _flight_record(db, segment)
    return None if resolved is None else str(resolved.get('status'))

def _any_flown(db: Mapping[str, Any], reservation: Mapping[str, Any]) -> bool | None:
    observed = []
    for segment in reservation.get('flights') or []:
        status = _status_for_segment(db, segment)
        if status is None:
            return None
        observed.append(status in {'flying', 'landed'} or dt.date.fromisoformat(str(segment['date'])) < NOW.date())
    return any(observed)

def _has_status(db: Mapping[str, Any], reservation: Mapping[str, Any], target: str) -> bool | None:
    statuses = [_status_for_segment(db, row) for row in reservation.get('flights') or []]
    if any((value is None for value in statuses)):
        return None
    return target in statuses

def _within_24h(reservation: Mapping[str, Any]) -> bool | None:
    created = reservation.get('created_at')
    if not isinstance(created, str):
        return None
    return NOW - dt.datetime.fromisoformat(created) <= dt.timedelta(hours=24)

def _net_refunds(reservation: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    payments = reservation.get('payment_history')
    if not isinstance(payments, list):
        return None
    totals: Counter[str] = Counter()
    for payment in payments:
        if not isinstance(payment, Mapping) or payment.get('payment_id') is None:
            return None
        amount = payment.get('amount')
        if not isinstance(amount, (int, float)):
            return None
        totals[str(payment['payment_id'])] += float(amount)
    return [{'payment_id': identifier, 'amount': round(amount, 2)} for identifier, amount in sorted(totals.items()) if amount > 0]

def _compensation_basis(*, db: Mapping[str, Any], user_id: str, reservation_id: str | None, committed_receipts: set[tuple[str, str]]) -> tuple[dict[str, Any] | None, bool]:
    reservations = db.get('reservations', {})
    candidates = []
    for identifier, reservation in reservations.items():
        if not isinstance(reservation, Mapping) or str(reservation.get('user_id')) != user_id:
            continue
        if reservation_id is not None and str(identifier) != reservation_id:
            continue
        cancelled = _has_status(db, reservation, 'cancelled')
        delayed = _has_status(db, reservation, 'delayed')
        if cancelled:
            event = 'cancelled'
        elif delayed:
            event = 'delayed'
        else:
            continue
        candidates.append({'event': event, 'passenger_count': len(reservation.get('passengers') or []), 'insurance': reservation.get('insurance'), 'cabin': reservation.get('cabin'), 'reservation_id': str(identifier), 'prior_related_change_completed': any((receipt_reservation == str(identifier) and receipt_schema in {'airline_cancel_effect', 'airline_flight_update_effect'} for receipt_schema, receipt_reservation in committed_receipts))})
    if len(candidates) == 1:
        return (candidates[0], False)
    return (None, len(candidates) > 1)

def _project_base_witnesses(*, db: Mapping[str, Any], required_witnesses: list[str], arguments: Mapping[str, Any], context_commitments: Mapping[str, Any], committed_receipts: set[tuple[str, str]] | None=None) -> ProjectionResult:
    required = {str(value) for value in required_witnesses}
    fields: dict[str, Any] = {}
    missing: set[str] = set()
    ambiguous: set[str] = set()
    receipts = set(committed_receipts or set())
    reservations = db.get('reservations', {})
    users = db.get('users', {})
    if 'reservations' in required:
        fields['reservations'] = copy.deepcopy(reservations)
    if 'users' in required:
        fields['users'] = copy.deepcopy(users)
    reservation = None
    reservation_id = arguments.get('reservation_id')
    if reservation_id is not None:
        reservation = reservations.get(str(reservation_id))
    if 'resolved_candidate_flights' in required:
        resolved = _resolved_flights(db, list(arguments.get('flights') or []))
        if resolved is None:
            missing.add('resolved_candidate_flights')
        else:
            fields['resolved_candidate_flights'] = resolved
    if 'route_and_trip_type_consistent' in required:
        resolved = fields.get('resolved_candidate_flights')
        source = reservation if isinstance(reservation, Mapping) else arguments
        if not isinstance(resolved, list):
            missing.add('route_and_trip_type_consistent')
        else:
            fields['route_and_trip_type_consistent'] = _route_consistent(resolved, str(source.get('origin', '')), str(source.get('destination', '')), str(source.get('flight_type', '')))
    if 'baggage_allowance_consistent' in required:
        source = reservation if isinstance(reservation, Mapping) else arguments
        user_id = str(arguments.get('user_id') or source.get('user_id', ''))
        user = users.get(user_id)
        allowance = _free_baggage_allowance(str(user.get('membership')), str(arguments.get('cabin', source.get('cabin'))), len(arguments.get('passengers', source.get('passengers')) or [])) if isinstance(user, Mapping) else None
        if allowance is None:
            missing.add('baggage_allowance_consistent')
        else:
            expected_nonfree = max(int(arguments.get('total_baggages', 0)) - allowance, 0)
            fields['baggage_allowance_consistent'] = int(arguments.get('nonfree_baggages', -1)) == expected_nonfree
    if 'any_prior_flight_flown' in required:
        value = _any_flown(db, reservation) if isinstance(reservation, Mapping) else None
        if value is None:
            missing.add('any_prior_flight_flown')
        else:
            fields['any_prior_flight_flown'] = value
    cancellation_fields = {'within_24h', 'airline_cancelled_flight', 'any_flight_segment_flown', 'net_refund_allocation'}
    if required & cancellation_fields:
        if not isinstance(reservation, Mapping):
            missing.update(required & cancellation_fields)
        else:
            values = {'within_24h': _within_24h(reservation), 'airline_cancelled_flight': _has_status(db, reservation, 'cancelled'), 'any_flight_segment_flown': _any_flown(db, reservation), 'net_refund_allocation': _net_refunds(reservation)}
            for name in required & cancellation_fields:
                if values[name] is None:
                    missing.add(name)
                else:
                    fields[name] = values[name]
    if 'compensation_basis' in required:
        user_id = str(arguments.get('user_id', ''))
        selected = context_commitments.get('compensation_reservation_id')
        basis, is_ambiguous = _compensation_basis(db=db, user_id=user_id, reservation_id=None if selected is None else str(selected), committed_receipts=receipts)
        if basis is None:
            (ambiguous if is_ambiguous else missing).add('compensation_basis')
        else:
            fields['compensation_basis'] = basis
    return ProjectionResult(fields=fields, missing_witnesses=tuple(sorted(missing)), ambiguous_witnesses=tuple(sorted(ambiguous)))

def _project_retained_prices(*, db: Mapping[str, Any], arguments: Mapping[str, Any], fields: dict[str, Any]) -> bool | None:
    reservation = db.get('reservations', {}).get(str(arguments.get('reservation_id')))
    resolved = fields.get('resolved_candidate_flights')
    requested = list(arguments.get('flights') or [])
    if not isinstance(reservation, Mapping) or not isinstance(resolved, list):
        return None
    if len(resolved) != len(requested):
        return None
    old_cabin = reservation.get('cabin')
    new_cabin = arguments.get('cabin')
    old_segments = {(str(row.get('flight_number')), str(row.get('date'))): row for row in reservation.get('flights') or [] if isinstance(row, Mapping)}
    for requested_row, projected_row in zip(requested, resolved):
        official_flight = db.get('flights', {}).get(str(requested_row.get('flight_number')))
        if not isinstance(official_flight, Mapping):
            return None
        for key in ('scheduled_departure_time_est', 'scheduled_arrival_time_est'):
            value = official_flight.get(key)
            if not isinstance(value, str) or not value:
                return None
            projected_row[key] = value
    if old_cabin == new_cabin:
        for requested_row, projected_row in zip(requested, resolved):
            key = (str(requested_row.get('flight_number')), str(requested_row.get('date')))
            retained = old_segments.get(key)
            if retained is None:
                continue
            booked_price = retained.get('price')
            prices = projected_row.get('prices')
            if not isinstance(booked_price, (int, float)) or not isinstance(prices, dict):
                return None
            prices[str(new_cabin)] = booked_price
    return True
_TIME_WITNESSES = {'time_constraint_conflicts', 'time_constraint_projection_valid'}

def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def _clock(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    clock = value.split('+', 1)[0]
    if len(clock) != 8 or clock[2] != ':' or clock[5] != ':':
        return None
    try:
        hour, minute, second = (int(part) for part in clock.split(':'))
    except ValueError:
        return None
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and (0 <= second <= 59)):
        return None
    return f'{hour:02d}:{minute:02d}:{second:02d}'

def _compare(value: str, comparator: str, threshold: str) -> bool:
    if comparator == 'lt':
        return value < threshold
    if comparator == 'le':
        return value <= threshold
    if comparator == 'gt':
        return value > threshold
    if comparator == 'ge':
        return value >= threshold
    raise ValueError(f'unsupported comparator: {comparator}')

def _itinerary_scopes(reservation: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    outbound: list[Mapping[str, Any]] = []
    inbound: list[Mapping[str, Any]] = []
    destination = str(reservation.get('destination', ''))
    reached_destination = False
    for row in rows:
        if reached_destination:
            inbound.append(row)
            continue
        outbound.append(row)
        if destination and str(row.get('destination', '')) == destination:
            reached_destination = True
    return {'all': list(rows), 'outbound': outbound, 'return': inbound}

def _project_time_constraints(*, db: Mapping[str, Any], arguments: Mapping[str, Any], fields: Mapping[str, Any], context_commitments: Mapping[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    constraints = context_commitments.get('time_constraints', [])
    if constraints in (None, []):
        return (True, [])
    if not isinstance(constraints, list):
        return (False, [])
    reservation = db.get('reservations', {}).get(str(arguments.get('reservation_id')))
    resolved = fields.get('resolved_candidate_flights')
    if not isinstance(reservation, Mapping) or not isinstance(resolved, list):
        return (False, [])
    rows = [row for row in resolved if isinstance(row, Mapping)]
    if len(rows) != len(resolved):
        return (False, [])
    scopes = _itinerary_scopes(reservation, rows)
    conflicts: list[dict[str, Any]] = []
    for constraint in constraints:
        if not isinstance(constraint, Mapping):
            return (False, [])
        field = str(constraint.get('field', ''))
        comparator = str(constraint.get('comparator', ''))
        threshold = _clock(constraint.get('threshold'))
        scope = str(constraint.get('scope', 'all'))
        scoped = scopes.get(scope)
        if field not in {'departure_time', 'arrival_time'} or threshold is None:
            return (False, [])
        if comparator not in {'lt', 'le', 'gt', 'ge'} or not scoped:
            return (False, [])
        selected = scoped[0] if field == 'departure_time' else scoped[-1]
        source_key = 'scheduled_departure_time_est' if field == 'departure_time' else 'scheduled_arrival_time_est'
        observed = _clock(selected.get(source_key))
        if observed is None:
            return (False, [])
        if _compare(observed, comparator, threshold):
            continue
        normalized = {'field': field, 'comparator': comparator, 'threshold': threshold, 'scope': scope}
        conflicts.append({'constraint_id': hashlib.sha256(_canonical(normalized).encode('utf-8')).hexdigest()[:12], 'prior_constraint': normalized, 'observed_value': observed, 'flight_number': selected.get('flight_number'), 'date': selected.get('date'), 'local_revision': 'Confirming this action explicitly revises the listed prior constraint for this action only.'})
    return (True, conflicts)

def project_airline_witnesses(*, db: Mapping[str, Any], required_witnesses: list[str], arguments: Mapping[str, Any], context_commitments: Mapping[str, Any], committed_receipts: set[tuple[str, str]] | None=None) -> ProjectionResult:
    base_required = [value for value in required_witnesses if value not in _TIME_WITNESSES]
    base = _project_base_witnesses(db=db, required_witnesses=base_required, arguments=arguments, context_commitments=context_commitments, committed_receipts=committed_receipts)
    fields = copy.deepcopy(base.fields)
    missing = set(base.missing_witnesses)
    if 'retained_price_projection_valid' in set(base_required):
        valid = _project_retained_prices(db=db, arguments=arguments, fields=fields)
        if valid is None:
            missing.add('retained_price_projection_valid')
        else:
            fields['retained_price_projection_valid'] = valid
    if _TIME_WITNESSES & set(required_witnesses):
        valid, conflicts = _project_time_constraints(db=db, arguments=arguments, fields=fields, context_commitments=context_commitments)
        fields['time_constraint_projection_valid'] = valid
        fields['time_constraint_conflicts'] = conflicts
        if not valid:
            missing.update(_TIME_WITNESSES & set(required_witnesses))
    return ProjectionResult(fields=fields, missing_witnesses=tuple(sorted(missing)), ambiguous_witnesses=base.ambiguous_witnesses)
__all__ = ['NOW', 'ProjectionResult', 'project_airline_witnesses']
