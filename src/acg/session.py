from __future__ import annotations
import copy
import hashlib
from dataclasses import dataclass, replace
from typing import Any, Mapping
from .core import AuthorizationClosureEngine, EffectRequest, expression_atoms
from .mediator import canonical
from .serialization import SerializationCandidate, _merged_proposal_fields

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

@dataclass
class SessionContext:
    key: str
    scope: str
    atoms: dict[str, str]
    schema: str
    lease: str
    candidate: SerializationCandidate
    witness_atoms: set[str]
    creation: bool = False
    dispatched: bool = False

    def request(self) -> EffectRequest:
        return EffectRequest(self.schema, copy.deepcopy(self.candidate.request.arguments), self.candidate.request.group_id, self.candidate.request.child_id)

class AuthorizationSession:

    def __init__(self):
        self.engine = AuthorizationClosureEngine({'effects': {}, 'derivations': []})
        self.contexts: dict[str, SessionContext] = {}
        self.events: list[dict[str, Any]] = []
        self._creation_slots: dict[str, tuple[int, str]] = {}

    def _ingest(self, event: Mapping[str, Any], *, engine=None) -> None:
        target = engine or self.engine
        row = target.ingest_event(event)
        if target is self.engine:
            self.events.append(copy.deepcopy(row))

    def install(self, candidate: SerializationCandidate) -> SessionContext:
        spec = candidate.effect_spec
        declaration = spec.get('authorization_scope', {})
        keys = declaration.get('arguments', list(candidate.request.arguments))
        if not all((key in candidate.request.arguments for key in keys)):
            raise ValueError('authorization scope argument missing')
        scope = digest({'namespace': declaration.get('namespace', candidate.request.schema_id), 'keys': {key: candidate.request.arguments[key] for key in keys}})
        spec_hash = digest(spec)
        lifecycle = declaration.get('lifecycle', 'resource')
        if lifecycle not in {'resource', 'new_effect'}:
            raise ValueError('unknown authorization scope lifecycle')
        if lifecycle == 'new_effect':
            slot = scope + ':' + spec_hash
            generation, previous_key = self._creation_slots.get(slot, (0, ''))
            if previous_key and self.contexts[previous_key].dispatched:
                generation += 1
            scope = digest({'resource_scope': scope, 'creation_instance': generation})
            self._creation_slots[slot] = (generation, scope + ':' + spec_hash)
        key = scope + ':' + spec_hash
        if key in self.contexts:
            context = self.contexts[key]
            context.candidate = copy.deepcopy(candidate)
            return context
        outputs = {str(rule['output']) for rule in spec.get('derivations', [])}
        fields = set(candidate.request.arguments) | set(spec.get('execution_metadata', {}).get('context_commitments', []))
        all_atoms = expression_atoms(spec) | outputs | fields
        effect = spec['effects'][candidate.request.schema_id]
        all_atoms |= set(effect.get('argument_bindings', {}).values()) | set(effect.get('proof_atoms', []))
        atoms = {atom: f'source:{scope}:{atom}' if atom in fields else f'node:{key}:{atom}' for atom in all_atoms}

        def rename(value):
            if isinstance(value, dict):
                if set(value) == {'const'}:
                    return copy.deepcopy(value)
                if set(value) == {'atom'}:
                    return {'atom': atoms[value['atom']]}
                return {k: rename(v) for k, v in value.items()}
            if isinstance(value, list):
                return [rename(v) for v in value]
            return copy.deepcopy(value)
        rules = rename(spec.get('derivations', []))
        for rule in rules:
            rule['output'] = atoms[rule['output']]
            rule['id'] = key + ':' + rule['id']
            if 'authority_parents' in rule:
                rule['authority_parents'] = [atoms[a] for a in rule['authority_parents']]
        schema = key + ':' + candidate.request.schema_id
        schema_spec = rename(effect)
        schema_spec['argument_bindings'] = {arg: atoms[atom] for arg, atom in effect.get('argument_bindings', {}).items()}
        schema_spec['proof_atoms'] = [atoms[atom] for atom in effect.get('proof_atoms', [])]
        lease = 'lease:' + schema
        schema_spec['proof_atoms'].append(lease)
        schema_spec['consumption_atom'] = lease
        schema_spec['consumption_binding'] = 'exact_arguments'
        schema_spec['budget'] = 1
        schema_spec['group_family'] = spec_hash + ':' + candidate.request.schema_id
        updated = copy.deepcopy(self.engine.spec)
        updated['derivations'].extend(rules)
        updated['effects'][schema] = schema_spec
        validated = AuthorizationClosureEngine(updated)
        self.engine.spec = validated.spec
        self.engine.rules_by_output = validated.rules_by_output
        self.engine.reverse_dependencies = validated.reverse_dependencies
        context = SessionContext(key, scope, atoms, schema, lease, copy.deepcopy(candidate), set(), creation=lifecycle == 'new_effect')
        self.contexts[key] = context
        return context

    def observe(self, context: SessionContext, state: Mapping, witnesses: Mapping) -> None:
        merged = {**state, **witnesses, **context.candidate.projected_witness_fields}
        fields = {context.atoms[atom]: value for atom, value in merged.items() if atom in context.atoms and (not context.atoms[atom].startswith('source:'))}
        removed = context.witness_atoms - set(fields)
        if removed:
            self._ingest({'event_type': 'revoke', 'atoms': sorted(removed)})
        changed = {atom: value for atom, value in fields.items() if atom not in self.engine.bindings or not self.engine.bindings[atom].active or canonical(self.engine.bindings[atom].value) != canonical(value)}
        if changed:
            self._ingest({'event_type': 'witness', 'fields': changed, 'evidence_ids': ['session-observation:' + digest(changed)]})
        context.witness_atoms = set(fields)

    def invalidate_projections(self) -> None:
        for context in self.contexts.values():
            atoms = [context.atoms[a] for a in context.candidate.projected_witness_fields if a in context.atoms]
            if atoms:
                self._ingest({'event_type': 'revoke', 'atoms': atoms})
            context.candidate = replace(context.candidate, projected_witness_fields={})

    def stage(self, context: SessionContext):
        scratch = copy.deepcopy(self.engine)
        fields = {context.atoms[atom]: value for atom, value in _merged_proposal_fields(context.candidate).items()}
        changes = {atom: value for atom, value in fields.items() if atom not in scratch.bindings or not scratch.bindings[atom].active or (not scratch.bindings[atom].authorized) or (canonical(scratch.bindings[atom].value) != canonical(value))}
        if changes:
            self._ingest({'event_type': 'proposal', 'fields': changes, 'evidence_ids': ['untrusted-session-proposal']}, engine=scratch)
        scratch.derive_all()
        return (scratch, changes)

    def mark_dispatched(self, context: SessionContext) -> None:
        context.dispatched = True

    def grant(self, context: SessionContext, events: tuple[dict, ...], *, renew: bool, engine=None) -> None:
        target = engine or self.engine
        for event in events:
            mapped = copy.deepcopy(event)
            if event['event_type'] == 'commitment':
                mapped['fields'] = {context.atoms[a]: value for a, value in event['fields'].items()}
                for atom, value in list(mapped['fields'].items()):
                    old = target.bindings.get(atom)
                    if old and old.active and old.authorized and (canonical(old.value) == canonical(value)):
                        del mapped['fields'][atom]
                if mapped['fields']:
                    mapped['event_type'] = 'revision' if any((a in target.bindings for a in mapped['fields'])) else 'commitment'
                    self._ingest(mapped, engine=target)
                if renew:
                    self._ingest({'event_type': 'commitment', 'fields': {context.lease: {'arguments': copy.deepcopy(context.candidate.request.arguments)}}, 'evidence_ids': event['evidence_ids']}, engine=target)
            elif event['event_type'] == 'confirm_derived':
                mapped['atom_id'] = context.atoms[event['atom_id']]
                self._ingest(mapped, engine=target)
            else:
                raise ValueError('unexpected closure grant event')
        target.derive_all()

    def publish(self, staged_engine, previous_event_count: int) -> None:
        new_events = copy.deepcopy(staged_engine.event_log[previous_event_count:])
        self.engine.__dict__.update(staged_engine.__dict__)
        self.events.extend(new_events)

    def fingerprint(self, context: SessionContext, engine) -> str:
        schema = engine.spec['effects'][context.schema]
        roots = set(schema['argument_bindings'].values()) | set(schema['proof_atoms']) | engine._policy_atoms(schema)
        nodes: dict[str, Any] = {}
        versions = engine._proof_closure(roots, nodes)
        group_state = None
        if context.candidate.request.group_id is not None:
            group = engine.groups.get(context.candidate.request.group_id)
            child = context.candidate.request.child_id
            group_state = None if group is None else {'grant': group.grant_version, 'shared': group.shared_version, 'member': group.member_versions.get(child), 'child': group.child_versions.get(child), 'revoked': child in group.revoked_children, 'remaining': group.remaining_budget.get(child)}
        return digest({'versions': versions, 'values': {a: engine.bindings[a].value for a in versions}, 'missing': sorted(roots - set(versions)), 'group': group_state})

    def snapshot(self) -> dict[str, Any]:
        return {'schema': 'acg-persistent-session-v1', 'contexts': len(self.contexts), 'atom_count': len(self.engine.bindings), 'event_count': len(self.events), 'versions': dict(self.engine.atom_versions), 'consumption': {digest(k): v for k, v in self.engine.remaining_budget.items()}}
