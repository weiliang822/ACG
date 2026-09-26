from __future__ import annotations
import copy
from dataclasses import dataclass, field
from typing import Any, Mapping
from .core import AuthorizationClosureEngine, EffectRequest
FEASIBLE = 'feasible'
REFUTED = 'refuted'
UNKNOWN = 'unknown'

@dataclass(frozen=True)
class SerializationCandidate:
    candidate_id: str
    request: EffectRequest
    effect_spec: dict[str, Any]
    predicted_transition: dict[str, Any] | None
    original_index: int
    context_commitments: dict[str, Any] = field(default_factory=dict)
    projected_witness_fields: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class PolicyProbe:
    state: str
    reason: str
    engine: AuthorizationClosureEngine
    decision_proof: dict[str, Any]

@dataclass(frozen=True)
class SerializationChoice:
    decision: str
    reason: str
    selected_candidate_id: str | None
    selected_index: int | None
    policy_states: dict[str, str]
    remaining_feasible_after: dict[str, int]

def probe_policy(candidate: SerializationCandidate, *, state_cache: Mapping[str, Any], witness_fields: Mapping[str, Any]) -> PolicyProbe:
    engine = AuthorizationClosureEngine(candidate.effect_spec)
    if state_cache:
        engine.ingest_event({'event_type': 'witness', 'fields': copy.deepcopy(dict(state_cache)), 'evidence_ids': ['serialization-probe:state']})
    combined_witnesses = copy.deepcopy({**dict(witness_fields), **candidate.projected_witness_fields})
    if combined_witnesses:
        engine.ingest_event({'event_type': 'witness', 'fields': combined_witnesses, 'evidence_ids': ['serialization-probe:witness']})
    engine.ingest_event({'event_type': 'proposal', 'fields': _merged_proposal_fields(candidate), 'evidence_ids': [f'serialization-probe:{candidate.candidate_id}']})
    decision = engine.prepare(candidate.request)
    if decision.reason == 'policy_refuted':
        state = REFUTED
    elif decision.reason == 'policy_unknown':
        state = UNKNOWN
    else:
        state = FEASIBLE
    return PolicyProbe(state, decision.reason, engine, copy.deepcopy(decision.proof))

def _merged_proposal_fields(candidate: SerializationCandidate) -> dict[str, Any]:
    overlap = set(candidate.context_commitments) & set(candidate.request.arguments)
    if any((candidate.context_commitments[key] != candidate.request.arguments[key] for key in overlap)):
        raise ValueError('context commitments conflict with executable arguments')
    return copy.deepcopy({**candidate.context_commitments, **candidate.request.arguments})

def _transition_value(engine: AuthorizationClosureEngine, expression: Mapping[str, Any]) -> Any:
    if 'const' in expression and len(expression) == 1:
        return copy.deepcopy(expression['const'])
    if 'atom' in expression and len(expression) == 1:
        binding = engine.bindings.get(str(expression['atom']))
        if binding is None or not binding.active:
            raise ValueError(f'predicted transition atom is unavailable: {expression['atom']}')
        return copy.deepcopy(binding.value)
    raise ValueError('predicted transition values must be one const or active atom')

def apply_predicted_transition(state_cache: Mapping[str, Any], candidate: SerializationCandidate, engine: AuthorizationClosureEngine) -> dict[str, Any]:
    updated = copy.deepcopy(dict(state_cache))
    transition = candidate.predicted_transition
    if transition is None:
        return updated
    collection_name = str(transition['collection'])
    key_argument = str(transition['key_argument'])
    if key_argument not in candidate.request.arguments:
        raise ValueError('predicted transition key is outside the candidate argument surface')
    collection = updated.get(collection_name)
    if not isinstance(collection, dict):
        raise ValueError('predicted transition collection is not a mapping')
    record_key = str(candidate.request.arguments[key_argument])
    record = collection.get(record_key)
    if not isinstance(record, Mapping):
        raise ValueError('predicted transition record is missing')
    projected = copy.deepcopy(dict(record))
    updates = transition.get('field_updates')
    if not isinstance(updates, Mapping) or not updates:
        raise ValueError('predicted transition needs non-empty field_updates')
    for field, expression in updates.items():
        if not isinstance(expression, Mapping):
            raise ValueError('predicted transition expressions must be data objects')
        projected[str(field)] = _transition_value(engine, expression)
    collection[record_key] = projected
    return updated

def choose_serialization_candidate(candidates: list[SerializationCandidate], *, state_cache: Mapping[str, Any], witness_fields: Mapping[str, Any]) -> SerializationChoice:
    if len(candidates) < 2:
        raise ValueError('serialization choice requires at least two candidates')
    probes = {candidate.candidate_id: probe_policy(candidate, state_cache=state_cache, witness_fields=witness_fields) for candidate in candidates}
    feasible = [candidate for candidate in candidates if probes[candidate.candidate_id].state == FEASIBLE]
    policy_states = {candidate.candidate_id: probes[candidate.candidate_id].state for candidate in candidates}
    if not feasible:
        return SerializationChoice('block', 'no_currently_policy_feasible_effect', None, None, policy_states, {})
    preservation: dict[str, int] = {}
    for candidate in feasible:
        transitioned = apply_predicted_transition(state_cache, candidate, probes[candidate.candidate_id].engine)
        preservation[candidate.candidate_id] = sum((probe_policy(other, state_cache=transitioned, witness_fields=witness_fields).state == FEASIBLE for other in candidates if other.candidate_id != candidate.candidate_id))
    maximum = max(preservation.values())
    best = [candidate for candidate in feasible if preservation[candidate.candidate_id] == maximum]
    if len(best) > 1 and maximum < len(candidates) - 1:
        return SerializationChoice('block', 'destructive_ordering_tie_requires_repair', None, None, policy_states, preservation)
    selected = min(best, key=lambda candidate: candidate.original_index)
    return SerializationChoice('select', 'maximizes_remaining_policy_feasibility', selected.candidate_id, selected.original_index, policy_states, preservation)

def actionable_witness_repair(*, policy_decision_proof: Mapping[str, Any], effect_spec: Mapping[str, Any], tool_manifest: Mapping[str, Any]) -> dict[str, Any]:
    unknown_policies = [str(row['policy_id']) for row in policy_decision_proof.get('policy_results', []) if row.get('state') == 'unknown']
    repairs = effect_spec.get('policy_repairs', {})
    atoms = sorted({str(atom) for policy_id in unknown_policies for atom in repairs.get(policy_id, [])})
    producers: dict[str, list[str]] = {atom: [] for atom in atoms}
    for tool_name, entry in tool_manifest.get('tools', {}).items():
        if not isinstance(entry, Mapping) or entry.get('kind') != 'witness':
            continue
        produced = {str(binding.get('atom_template')) for binding in entry.get('bindings', []) if isinstance(binding, Mapping) and isinstance(binding.get('atom_template'), str) and ('{' not in str(binding.get('atom_template')))}
        produced.update((str(patch.get('collection')) for patch in entry.get('state_patches', []) if isinstance(patch, Mapping) and patch.get('collection')))
        for atom in atoms:
            if atom in produced:
                producers[atom].append(str(tool_name))
    return {'unknown_policies': unknown_policies, 'required_witness_atoms': atoms, 'native_witness_tools': {atom: sorted(names) for atom, names in producers.items()}, 'free_text_can_satisfy': False}
__all__ = ['FEASIBLE', 'REFUTED', 'UNKNOWN', 'PolicyProbe', 'SerializationCandidate', 'SerializationChoice', 'actionable_witness_repair', 'apply_predicted_transition', 'choose_serialization_candidate', 'probe_policy']
