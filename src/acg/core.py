from __future__ import annotations
import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
AUTHORIZE = 'authorize'
ASK = 'ask'
BLOCK = 'block'
SATISFIED = 'satisfied'
REFUTED = 'refuted'
UNKNOWN = 'unknown'

def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

@dataclass
class Binding:
    atom_id: str
    value: Any
    kind: str
    version: int
    evidence_ids: tuple[str, ...]
    active: bool = True
    authorized: bool = False
    authority_sources: tuple[str, ...] = ()
    parents: tuple[str, ...] = ()
    parent_versions: tuple[tuple[str, int], ...] = ()
    rule_id: str | None = None
    authority_mode: str | None = None

@dataclass
class GroupGrant:
    group_id: str
    schema_id: str
    grant_version: int
    shared_version: int
    members: tuple[str, ...]
    member_versions: dict[str, int]
    shared_arguments: dict[str, Any]
    child_arguments: dict[str, dict[str, Any]]
    child_versions: dict[str, int]
    remaining_budget: dict[str, int]
    evidence_ids: tuple[str, ...]
    revoked_children: set[str] = field(default_factory=set)

@dataclass(frozen=True)
class EffectRequest:
    schema_id: str
    arguments: dict[str, Any]
    group_id: str | None = None
    child_id: str | None = None

@dataclass(frozen=True)
class Decision:
    decision: str
    reason: str
    repair_atoms: tuple[str, ...] = ()
    proof: dict[str, Any] = field(default_factory=dict)
    reservation_id: str | None = None

class UnknownExpression(ValueError):
    pass

def expression_atoms(expression: Any) -> set[str]:
    if isinstance(expression, Mapping):
        if set(expression) == {'const'}:
            return set()
        if 'atom' in expression:
            return {str(expression['atom'])}
        atoms: set[str] = set()
        for value in expression.values():
            atoms.update(expression_atoms(value))
        return atoms
    if isinstance(expression, list):
        atoms: set[str] = set()
        for value in expression:
            atoms.update(expression_atoms(value))
        return atoms
    return set()

class AuthorizationClosureEngine:

    def __init__(self, spec: Mapping[str, Any]):
        self.spec = copy.deepcopy(dict(spec))
        self.bindings: dict[str, Binding] = {}
        self.groups: dict[str, GroupGrant] = {}
        self.atom_versions: dict[str, int] = {}
        self.group_versions: dict[str, int] = {}
        self.reverse_dependencies: dict[str, set[str]] = {}
        self.rules_by_output: dict[str, dict[str, Any]] = {}
        self.remaining_budget: dict[str, int] = {}
        self.reserved_budget: dict[str, int] = {}
        self.reservations: dict[str, dict[str, Any]] = {}
        self.event_log: list[dict[str, Any]] = []
        self._reservation_counter = 0
        self._compile_spec()

    @staticmethod
    def _reject_executable_values(value: Any, path: str='spec') -> None:
        if callable(value):
            raise ValueError(f'executable callback is forbidden at {path}')
        if isinstance(value, Mapping):
            for key, child in value.items():
                AuthorizationClosureEngine._reject_executable_values(child, f'{path}.{key}')
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                AuthorizationClosureEngine._reject_executable_values(child, f'{path}[{index}]')

    @staticmethod
    def _validate_expression(expression: Any, *, path: str) -> None:
        known_ops = {'add', 'sub', 'mul', 'round2', 'map_get', 'eq', 'le', 'in', 'and', 'or', 'not', 'lt', 'gt', 'ge', 'abs', 'sum', 'if', 'map_list', 'index_by', 'sort', 'zip_records', 'normalize_space', 'starts_with', 'len', 'all', 'keys', 'multiset_within', 'paired_nested_lookup', 'get_or', 'max', 'pluck', 'paired_nested_contains', 'record', 'list', 'filter_eq', 'map_records'}
        if isinstance(expression, Mapping):
            terminals = {key for key in ('atom', 'candidate', 'const', 'local') if key in expression}
            if terminals:
                if len(terminals) != 1 or len(expression) != 1:
                    raise ValueError(f'invalid terminal expression at {path}')
                return
            op = expression.get('op')
            if op not in known_ops:
                raise ValueError(f'unsupported declarative operation at {path}: {op}')
            if op == 'record':
                fields = expression.get('fields')
                if not isinstance(fields, Mapping):
                    raise ValueError(f'record fields must be an object at {path}')
                for key, child in fields.items():
                    AuthorizationClosureEngine._validate_expression(child, path=f'{path}.fields.{key}')
                return
            if op == 'map_records':
                if not isinstance(expression.get('var'), str):
                    raise ValueError(f'map_records var must be a string at {path}')
                if 'rows' not in expression or 'template' not in expression:
                    raise ValueError(f'map_records requires rows and template at {path}')
                AuthorizationClosureEngine._validate_expression(expression['rows'], path=f'{path}.rows')
                AuthorizationClosureEngine._validate_expression(expression['template'], path=f'{path}.template')
                return
            args = expression.get('args')
            if not isinstance(args, list):
                raise ValueError(f'expression args must be a list at {path}')
            for index, child in enumerate(args):
                AuthorizationClosureEngine._validate_expression(child, path=f'{path}.args[{index}]')
            return
        if isinstance(expression, list):
            for index, child in enumerate(expression):
                AuthorizationClosureEngine._validate_expression(child, path=f'{path}[{index}]')
            return
        if isinstance(expression, (str, int, float, bool)) or expression is None:
            return
        raise ValueError(f'non-data expression value at {path}')

    @staticmethod
    def _authority_config(rule: Mapping[str, Any]) -> tuple[str, Any | None]:
        value = rule.get('authority', 'inherit')
        if isinstance(value, str):
            return (value, None)
        if isinstance(value, Mapping):
            return (str(value.get('mode')), value.get('predicate'))
        raise ValueError('authority must be a string or declarative object')

    def _compile_spec(self) -> None:
        self._reject_executable_values(self.spec)
        effects = self.spec.get('effects', {})
        if not isinstance(effects, Mapping):
            raise ValueError('effects must be a mapping')
        for schema_id, schema in effects.items():
            if not isinstance(schema, Mapping):
                raise ValueError(f'effect schema must be an object: {schema_id}')
            bindings = schema.get('argument_bindings', {})
            if not isinstance(bindings, Mapping):
                raise ValueError(f'argument_bindings must be an object: {schema_id}')
            proof_atoms = schema.get('proof_atoms', [])
            if not isinstance(proof_atoms, list) or not all((isinstance(value, str) for value in proof_atoms)):
                raise ValueError(f'proof_atoms must be a string list: {schema_id}')
            for index, policy in enumerate(schema.get('policies', [])):
                expression = policy['expression'] if isinstance(policy, Mapping) and 'expression' in policy else policy
                self._validate_expression(expression, path=f'effects.{schema_id}.policies[{index}]')
            budget = int(schema.get('budget', 1))
            if budget <= 0:
                raise ValueError(f'effect budget must be positive: {schema_id}')
        derivations = self.spec.get('derivations', [])
        if not isinstance(derivations, list):
            raise ValueError('derivations must be a list')
        all_outputs = {str(rule.get('output')) for rule in derivations if isinstance(rule, Mapping) and 'output' in rule}
        compiled_outputs: set[str] = set()
        for rule in derivations:
            if not isinstance(rule, Mapping):
                raise ValueError('derivation rules must be objects')
            output = str(rule['output'])
            if output in self.rules_by_output:
                raise ValueError(f'duplicate derivation output: {output}')
            self._validate_expression(rule['expression'], path=f'derivations.{output}.expression')
            authority, predicate = self._authority_config(rule)
            if authority not in {'inherit', 'confirm', 'bounded'}:
                raise ValueError(f'unsupported authority mode: {authority}')
            if authority == 'bounded':
                if predicate is None:
                    raise ValueError(f'bounded authority needs a predicate: {output}')
                self._validate_expression(predicate, path=f'derivations.{output}.authority.predicate')
            elif predicate is not None:
                raise ValueError(f'only bounded authority accepts a predicate: {output}')
            self.rules_by_output[output] = copy.deepcopy(dict(rule))
            parents = expression_atoms(rule['expression'])
            if predicate is not None:
                parents |= expression_atoms(predicate)
            authority_parents = rule.get('authority_parents')
            if authority_parents is not None:
                if not isinstance(authority_parents, list) or not all((isinstance(atom, str) for atom in authority_parents)) or len(authority_parents) != len(set(authority_parents)) or (not set(authority_parents) <= parents):
                    raise ValueError(f'authority_parents must be unique dependency atoms: {output}')
            forward_references = (parents & all_outputs) - compiled_outputs
            if forward_references:
                raise ValueError(f'derivations must be topologically ordered; {output} depends on {sorted(forward_references)}')
            for parent in parents:
                if parent == output:
                    raise ValueError(f'self-dependent derivation: {output}')
                self.reverse_dependencies.setdefault(parent, set()).add(output)
            compiled_outputs.add(output)

    def _next_atom_version(self, atom_id: str) -> int:
        version = self.atom_versions.get(atom_id, 0) + 1
        self.atom_versions[atom_id] = version
        return version

    def _next_group_version(self, group_id: str) -> int:
        version = self.group_versions.get(group_id, 0) + 1
        self.group_versions[group_id] = version
        return version

    def dependency_closure(self, changed_atoms: set[str]) -> set[str]:
        affected: set[str] = set()
        frontier = list(changed_atoms)
        while frontier:
            source = frontier.pop()
            for dependent in self.reverse_dependencies.get(source, set()):
                if dependent not in affected:
                    affected.add(dependent)
                    frontier.append(dependent)
        return affected

    def minimal_repair_frontier(self, repair_atoms: set[str]) -> set[str]:
        redundant: set[str] = set()
        for source in repair_atoms:
            frontier = [source]
            visited = {source}
            while frontier:
                parent = frontier.pop()
                for child in self.reverse_dependencies.get(parent, set()):
                    if child in visited:
                        continue
                    visited.add(child)
                    rule = self.rules_by_output.get(child)
                    if rule is None:
                        continue
                    mode, _ = self._authority_config(rule)
                    if mode != 'inherit':
                        continue
                    if child in repair_atoms:
                        redundant.add(child)
                    frontier.append(child)
        return repair_atoms - redundant

    def _invalidate_descendants(self, changed_atoms: set[str]) -> set[str]:
        affected = self.dependency_closure(changed_atoms)
        invalidated: set[str] = set()
        for atom_id in affected:
            binding = self.bindings.get(atom_id)
            if binding is not None and binding.active:
                binding.active = False
                binding.authorized = False
                invalidated.add(atom_id)
        return invalidated

    def commit_atom(self, atom_id: str, value: Any, *, kind: str, evidence_ids: tuple[str, ...], authorized: bool) -> set[str]:
        if kind not in {'commitment', 'witness'}:
            raise ValueError('external atoms must be commitments or witnesses')
        if not evidence_ids:
            raise ValueError('evidence is required')
        previous = self.bindings.get(atom_id)
        invalidated = self._invalidate_descendants({atom_id})
        version = self._next_atom_version(atom_id)
        sources = (f'{atom_id}@{version}',) if kind == 'commitment' and authorized else ()
        self.bindings[atom_id] = Binding(atom_id=atom_id, value=copy.deepcopy(value), kind=kind, version=version, evidence_ids=tuple(evidence_ids), active=True, authorized=authorized, authority_sources=sources)
        return invalidated

    def revoke_atom(self, atom_id: str) -> set[str]:
        binding = self.bindings.get(atom_id)
        if binding is None:
            return set()
        binding.active = False
        binding.authorized = False
        return {atom_id, *self._invalidate_descendants({atom_id})}

    def confirm_derived(self, atom_id: str, evidence_id: str) -> None:
        binding = self.bindings.get(atom_id)
        if binding is None or not binding.active or binding.kind != 'derived':
            raise ValueError(f'no active derived atom to confirm: {atom_id}')
        binding.authorized = True
        binding.authority_sources = tuple(dict.fromkeys((*binding.authority_sources, f'confirmation:{evidence_id}')))
        binding.evidence_ids = tuple(dict.fromkeys((*binding.evidence_ids, evidence_id)))

    def ingest_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise ValueError('typed events must be objects')
        event_type = str(event.get('event_type', ''))
        before = {atom_id for atom_id, binding in self.bindings.items() if binding.active}
        invalidated: set[str] = set()
        changed: set[str] = set()
        if event_type in {'commitment', 'revision', 'witness', 'proposal'}:
            fields = event.get('fields')
            evidence_ids = tuple((str(value) for value in event.get('evidence_ids', [])))
            if not isinstance(fields, Mapping) or not evidence_ids:
                raise ValueError('field events need fields and evidence_ids')
            kind = 'witness' if event_type == 'witness' else 'commitment'
            authorized = kind == 'commitment' and event_type != 'proposal'
            for atom_id_value, value in fields.items():
                atom_id = str(atom_id_value)
                old = self.bindings.get(atom_id)
                if old is None or canonical(old.value) != canonical(value):
                    changed.add(atom_id)
                invalidated.update(self.commit_atom(atom_id, value, kind=kind, evidence_ids=evidence_ids, authorized=authorized))
            self.derive_all()
        elif event_type == 'revoke':
            atoms = tuple((str(value) for value in event.get('atoms', [])))
            if not atoms:
                raise ValueError('revoke needs at least one atom')
            changed.update(atoms)
            for atom_id in atoms:
                invalidated.update(self.revoke_atom(atom_id))
        elif event_type == 'confirm_derived':
            atom_id = str(event['atom_id'])
            self.confirm_derived(atom_id, str(event['evidence_id']))
            changed.add(atom_id)
        elif event_type == 'group_grant':
            self.register_group(group_id=str(event['group_id']), schema_id=str(event['schema_id']), members=tuple((str(value) for value in event['members'])), shared_arguments=event.get('shared_arguments', {}), child_arguments=event['child_arguments'], budget_per_child=int(event.get('budget_per_child', 1)), evidence_ids=tuple((str(value) for value in event['evidence_ids'])))
        elif event_type == 'group_child_revision':
            self.revise_group_child(str(event['group_id']), str(event['child_id']), event['arguments'], str(event['evidence_id']))
        elif event_type == 'group_shared_revision':
            self.revise_group_shared(str(event['group_id']), event['shared_arguments'], str(event['evidence_id']), event.get('budget_by_child'))
        elif event_type == 'group_member_add':
            self.add_group_child(str(event['group_id']), str(event['child_id']), event['arguments'], int(event.get('budget', 1)), str(event['evidence_id']))
        elif event_type == 'group_child_revoke':
            self.revoke_group_child(str(event['group_id']), str(event['child_id']), str(event['evidence_id']))
        else:
            raise ValueError(f'unsupported typed event: {event_type}')
        after = {atom_id for atom_id, binding in self.bindings.items() if binding.active}
        row = {'event_index': len(self.event_log) + 1, 'event_type': event_type, 'changed_atoms': sorted(changed), 'invalidated_atoms': sorted(invalidated), 'preserved_active_atoms': sorted((before & after) - changed - invalidated), 'active_atoms_after': sorted(after)}
        self.event_log.append(copy.deepcopy(row))
        return row

    def _eval(self, expression: Any, *, candidate: Mapping[str, Any] | None=None, local: Mapping[str, Any] | None=None) -> Any:
        if isinstance(expression, Mapping):
            if 'atom' in expression:
                atom_id = str(expression['atom'])
                binding = self.bindings.get(atom_id)
                if binding is None or not binding.active:
                    raise UnknownExpression(atom_id)
                return copy.deepcopy(binding.value)
            if 'candidate' in expression:
                key = str(expression['candidate'])
                if candidate is None or key not in candidate:
                    raise UnknownExpression(f'candidate:{key}')
                return copy.deepcopy(candidate[key])
            if 'local' in expression:
                key = str(expression['local'])
                if local is None or key not in local:
                    raise UnknownExpression(f'local:{key}')
                return copy.deepcopy(local[key])
            if 'const' in expression:
                return copy.deepcopy(expression['const'])
            op = expression.get('op')
            if op == 'record':
                return {str(key): self._eval(value, candidate=candidate, local=local) for key, value in expression['fields'].items()}
            if op == 'map_records':
                rows = self._eval(expression['rows'], candidate=candidate, local=local)
                variable = str(expression['var'])
                output = []
                for row in rows:
                    child_local = dict(local or {})
                    child_local[variable] = row
                    output.append(self._eval(expression['template'], candidate=candidate, local=child_local))
                return output
            args = [self._eval(value, candidate=candidate, local=local) for value in expression.get('args', [])]
            if op == 'add':
                return sum(args)
            if op == 'sub':
                if len(args) != 2:
                    raise ValueError('sub requires two arguments')
                return args[0] - args[1]
            if op == 'mul':
                value = 1
                for arg in args:
                    value *= arg
                return value
            if op == 'round2':
                if len(args) != 1:
                    raise ValueError('round2 requires one argument')
                return round(float(args[0]) + 1e-12, 2)
            if op == 'map_get':
                if len(args) != 2:
                    raise ValueError('map_get requires mapping and key')
                return args[0][args[1]]
            if op == 'eq':
                return canonical(args[0]) == canonical(args[1])
            if op == 'le':
                return args[0] <= args[1]
            if op == 'in':
                return args[0] in args[1]
            if op == 'and':
                return all((bool(value) for value in args))
            if op == 'or':
                return any((bool(value) for value in args))
            if op == 'not':
                if len(args) != 1:
                    raise ValueError('not requires one argument')
                return not bool(args[0])
            if op == 'lt':
                return args[0] < args[1]
            if op == 'gt':
                return args[0] > args[1]
            if op == 'ge':
                return args[0] >= args[1]
            if op == 'abs':
                if len(args) != 1:
                    raise ValueError('abs requires one argument')
                return abs(args[0])
            if op == 'sum':
                if len(args) == 1 and isinstance(args[0], list):
                    return sum(args[0])
                return sum(args)
            if op == 'if':
                if len(args) != 3:
                    raise ValueError('if requires condition, true value, false value')
                return args[1] if bool(args[0]) else args[2]
            if op == 'map_list':
                if len(args) != 2:
                    raise ValueError('map_list requires mapping and keys')
                return [args[0][key] for key in args[1]]
            if op == 'index_by':
                if len(args) != 3:
                    raise ValueError('index_by requires rows, key field, value field')
                return {row[args[1]]: row[args[2]] for row in args[0]}
            if op == 'sort':
                if len(args) != 1:
                    raise ValueError('sort requires one list')
                return sorted(args[0], key=canonical)
            if op == 'zip_records':
                if len(args) != 4 or len(args[0]) != len(args[1]):
                    raise ValueError('zip_records requires equal lists and two field names')
                return sorted([{str(args[2]): left, str(args[3]): right} for left, right in zip(args[0], args[1])], key=canonical)
            if op == 'normalize_space':
                if len(args) != 1:
                    raise ValueError('normalize_space requires one value')
                return ' '.join(str(args[0]).strip().split())
            if op == 'starts_with':
                if len(args) != 2:
                    raise ValueError('starts_with requires value and prefix')
                return str(args[0]).startswith(str(args[1]))
            if op == 'len':
                if len(args) != 1:
                    raise ValueError('len requires one value')
                return len(args[0])
            if op == 'all':
                if len(args) != 1:
                    raise ValueError('all requires one list')
                return all((bool(value) for value in args[0]))
            if op == 'keys':
                if len(args) != 1 or not isinstance(args[0], Mapping):
                    raise ValueError('keys requires one mapping')
                return list(args[0].keys())
            if op == 'multiset_within':
                if len(args) != 2:
                    raise ValueError('multiset_within requires requested and available lists')
                requested_counts = {value: args[0].count(value) for value in set(args[0])}
                available_counts = {value: args[1].count(value) for value in set(args[1])}
                return all((count <= available_counts.get(value, 0) for value, count in requested_counts.items()))
            if op == 'paired_nested_lookup':
                if len(args) != 5 or len(args[1]) != len(args[3]):
                    raise ValueError('paired_nested_lookup requires root, outer keys, middle key, inner keys, value key')
                return [args[0][outer][args[2]][inner][args[4]] for outer, inner in zip(args[1], args[3])]
            if op == 'get_or':
                if len(args) != 3 or not isinstance(args[0], Mapping):
                    raise ValueError('get_or requires mapping, key, default')
                return args[0].get(args[1], args[2])
            if op == 'max':
                if len(args) == 1 and isinstance(args[0], list):
                    return max(args[0])
                return max(args)
            if op == 'pluck':
                if len(args) != 2:
                    raise ValueError('pluck requires rows and field')
                return [row[args[1]] for row in args[0]]
            if op == 'paired_nested_contains':
                if len(args) != 4 or len(args[1]) != len(args[3]):
                    raise ValueError('paired_nested_contains requires root, outer keys, middle key, inner keys')
                return [outer in args[0] and args[2] in args[0][outer] and (inner in args[0][outer][args[2]]) for outer, inner in zip(args[1], args[3])]
            if op == 'list':
                return args
            if op == 'filter_eq':
                if len(args) != 3:
                    raise ValueError('filter_eq requires rows, field, value')
                return [row for row in args[0] if row.get(args[1]) == args[2]]
            raise ValueError(f'unsupported declarative operation: {op}')
        if isinstance(expression, list):
            return [self._eval(value, candidate=candidate, local=local) for value in expression]
        return copy.deepcopy(expression)

    def _authority_parent_atoms(self, rule: Mapping[str, Any], parents: tuple[str, ...]) -> tuple[str, ...]:
        if 'authority_parents' in rule:
            return tuple(rule['authority_parents'])
        roles: dict[str, bool] = {}

        def carries_authority(atom: str) -> bool:
            if atom in roles:
                return roles[atom]
            parent_rule = self.rules_by_output.get(atom)
            if parent_rule is None:
                binding = self.bindings.get(atom)
                roles[atom] = binding is None or binding.kind != 'witness'
            else:
                mode, predicate = self._authority_config(parent_rule)
                dependencies = expression_atoms(parent_rule['expression'])
                if predicate is not None:
                    dependencies |= expression_atoms(predicate)
                declared = parent_rule.get('authority_parents')
                roles[atom] = mode == 'confirm' or (bool(declared) if declared is not None else any((carries_authority(p) for p in dependencies)))
            return roles[atom]
        return tuple((atom for atom in parents if carries_authority(atom)))

    def derive_all(self) -> None:
        for rule in self.spec.get('derivations', []):
            output = str(rule['output'])
            authority_mode, authority_predicate = self._authority_config(rule)
            parent_atoms = expression_atoms(rule['expression'])
            if authority_predicate is not None:
                parent_atoms |= expression_atoms(authority_predicate)
            parents = tuple(sorted(parent_atoms))
            try:
                value = self._eval(rule['expression'])
            except (UnknownExpression, KeyError, IndexError, TypeError, ValueError):
                binding = self.bindings.get(output)
                if binding is not None:
                    binding.active = False
                    binding.authorized = False
                continue
            previous = self.bindings.get(output)
            parent_bindings = [self.bindings[parent] for parent in parents if parent in self.bindings and self.bindings[parent].active]
            parent_versions = tuple(((binding.atom_id, binding.version) for binding in parent_bindings))
            same_lineage = previous is not None and previous.active and (canonical(previous.value) == canonical(value)) and (previous.parents == parents) and (previous.parent_versions == parent_versions) and (previous.rule_id == str(rule['id']))
            if not same_lineage:
                self._invalidate_descendants({output})
            sources = tuple(dict.fromkeys((source for binding in parent_bindings if binding.authorized for source in binding.authority_sources)))
            required_authority = self._authority_parent_atoms(rule, parents)
            all_parents_authorized = bool(required_authority) and all((atom in self.bindings and self.bindings[atom].active and self.bindings[atom].authorized and bool(self.bindings[atom].authority_sources) for atom in required_authority))
            authority_mode, authority_predicate = self._authority_config(rule)
            if authority_mode == 'inherit':
                authorized = all_parents_authorized
            elif authority_mode == 'confirm':
                authorized = bool(same_lineage and previous and previous.authorized)
            else:
                try:
                    authorized = all_parents_authorized and bool(self._eval(authority_predicate, local={'derived': value}))
                except (UnknownExpression, KeyError, IndexError, TypeError, ValueError):
                    authorized = False
            evidence = tuple(dict.fromkeys((evidence_id for binding in parent_bindings for evidence_id in binding.evidence_ids)))
            if same_lineage and previous is not None:
                version = previous.version
                evidence = tuple(dict.fromkeys((*previous.evidence_ids, *evidence)))
                if previous.authorized and authority_mode == 'confirm':
                    sources = previous.authority_sources
            else:
                version = self._next_atom_version(output)
            self.bindings[output] = Binding(atom_id=output, value=copy.deepcopy(value), kind='derived', version=version, evidence_ids=evidence, active=True, authorized=authorized, authority_sources=sources, parents=parents, parent_versions=parent_versions, rule_id=str(rule['id']), authority_mode=authority_mode)

    def register_group(self, *, group_id: str, schema_id: str, members: tuple[str, ...], shared_arguments: Mapping[str, Any], child_arguments: Mapping[str, Mapping[str, Any]], budget_per_child: int, evidence_ids: tuple[str, ...]) -> None:
        if schema_id not in self.spec.get('effects', {}):
            raise ValueError(f'unknown effect schema: {schema_id}')
        if set(members) != set(child_arguments):
            raise ValueError('every group member needs exactly one complete child mapping')
        if len(members) != len(set(members)) or budget_per_child <= 0:
            raise ValueError('invalid finite group')
        for arguments in child_arguments.values():
            if any((key in arguments and canonical(arguments[key]) != canonical(value) for key, value in shared_arguments.items())):
                raise ValueError('child bindings conflict with shared group bindings')
        self.groups[group_id] = GroupGrant(group_id=group_id, schema_id=schema_id, grant_version=self._next_group_version(group_id), shared_version=1, members=tuple(members), member_versions={str(child): 1 for child in members}, shared_arguments=copy.deepcopy(dict(shared_arguments)), child_arguments={str(child): copy.deepcopy(dict(arguments)) for child, arguments in child_arguments.items()}, child_versions={str(child): 1 for child in members}, remaining_budget={str(child): budget_per_child for child in members}, evidence_ids=tuple(evidence_ids))

    def revise_group_child(self, group_id: str, child_id: str, arguments: Mapping[str, Any], evidence_id: str) -> None:
        group = self.groups[group_id]
        if child_id not in group.members:
            raise ValueError('cannot revise a non-member child')
        if any((key in arguments and canonical(arguments[key]) != canonical(value) for key, value in group.shared_arguments.items())):
            raise ValueError('child bindings conflict with shared group bindings')
        group.child_arguments[child_id] = copy.deepcopy(dict(arguments))
        group.child_versions[child_id] += 1
        group.remaining_budget[child_id] = max(group.remaining_budget.get(child_id, 0), 1)
        group.evidence_ids = tuple(dict.fromkeys((*group.evidence_ids, evidence_id)))

    def revise_group_shared(self, group_id: str, shared_arguments: Mapping[str, Any], evidence_id: str, budget_by_child: Mapping[str, int] | None=None) -> None:
        group = self.groups[group_id]
        if any((key in arguments and canonical(arguments[key]) != canonical(value) for arguments in group.child_arguments.values() for key, value in shared_arguments.items())):
            raise ValueError('shared bindings conflict with child group bindings')
        if budget_by_child is not None:
            unknown = set(budget_by_child) - set(group.members)
            if unknown or any((int(value) < 0 for value in budget_by_child.values())):
                raise ValueError('invalid explicit shared-revision budget')
        group.shared_arguments = copy.deepcopy(dict(shared_arguments))
        group.shared_version += 1
        if budget_by_child is not None:
            for child_id, value in budget_by_child.items():
                group.remaining_budget[str(child_id)] = int(value)
        group.evidence_ids = tuple(dict.fromkeys((*group.evidence_ids, evidence_id)))

    def add_group_child(self, group_id: str, child_id: str, arguments: Mapping[str, Any], budget: int, evidence_id: str) -> None:
        group = self.groups[group_id]
        if child_id in group.members or budget <= 0:
            raise ValueError('group member addition must be new and have positive budget')
        if any((key in arguments and canonical(arguments[key]) != canonical(value) for key, value in group.shared_arguments.items())):
            raise ValueError('child bindings conflict with shared group bindings')
        group.members = (*group.members, child_id)
        group.member_versions[child_id] = 1
        group.child_arguments[child_id] = copy.deepcopy(dict(arguments))
        group.child_versions[child_id] = 1
        group.remaining_budget[child_id] = int(budget)
        group.evidence_ids = tuple(dict.fromkeys((*group.evidence_ids, evidence_id)))

    def revoke_group_child(self, group_id: str, child_id: str, evidence_id: str) -> None:
        group = self.groups[group_id]
        if child_id not in group.members:
            raise ValueError('cannot revoke a non-member child')
        group.revoked_children.add(child_id)
        group.child_versions[child_id] += 1
        group.evidence_ids = tuple(dict.fromkeys((*group.evidence_ids, evidence_id)))

    def _effect_schema(self, schema_id: str) -> dict[str, Any]:
        try:
            return self.spec['effects'][schema_id]
        except KeyError as exc:
            raise ValueError(f'unknown effect schema: {schema_id}') from exc

    def _evaluate_policies(self, schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> tuple[Decision | None, list[dict[str, Any]]]:
        results: list[dict[str, Any]] = []
        unknown_ids: list[str] = []
        for index, policy in enumerate(schema.get('policies', [])):
            if isinstance(policy, Mapping) and 'expression' in policy:
                policy_id = str(policy.get('id', index))
                expression = policy['expression']
            else:
                policy_id = str(index)
                expression = policy
            try:
                satisfied = bool(self._eval(expression, candidate=arguments))
            except (UnknownExpression, KeyError):
                results.append({'policy_id': policy_id, 'state': UNKNOWN})
                unknown_ids.append(policy_id)
                continue
            if not satisfied:
                results.append({'policy_id': policy_id, 'state': REFUTED})
                return (Decision(BLOCK, 'policy_refuted', proof={'policy_results': copy.deepcopy(results)}), results)
            results.append({'policy_id': policy_id, 'state': SATISFIED})
        if unknown_ids:
            return (Decision(ASK, 'policy_unknown', repair_atoms=tuple((f'policy:{value}' for value in unknown_ids)), proof={'policy_results': copy.deepcopy(results)}), results)
        return (None, results)

    def _new_reservation(self, *, semantic_key: str, proof: dict[str, Any], group_ref: tuple[str, str] | None) -> Decision:
        available = self.remaining_budget.get(semantic_key, 1)
        reserved = self.reserved_budget.get(semantic_key, 0)
        if available - reserved <= 0:
            return Decision(BLOCK, 'authorization_budget_exhausted', proof=proof)
        self.reserved_budget[semantic_key] = reserved + 1
        self._reservation_counter += 1
        reservation_id = f'prepare-{self._reservation_counter}'
        self.reservations[reservation_id] = {'semantic_key': semantic_key, 'proof': copy.deepcopy(proof), 'group_ref': group_ref}
        return Decision(AUTHORIZE, 'closure_proof_prepared', proof=proof, reservation_id=reservation_id)

    def prepare(self, request: EffectRequest) -> Decision:
        schema = self._effect_schema(request.schema_id)
        policy_decision, policy_results = self._evaluate_policies(schema, request.arguments)
        if policy_decision is not None:
            return policy_decision
        if request.group_id is not None or request.child_id is not None:
            if request.group_id is None or request.child_id is None:
                return Decision(BLOCK, 'incomplete_group_reference')
            group = self.groups.get(request.group_id)
            if group is None or (group.schema_id != request.schema_id and (not schema.get('group_family') or self._effect_schema(group.schema_id).get('group_family') != schema.get('group_family'))):
                return Decision(BLOCK, 'group_grant_missing')
            if request.child_id not in group.members:
                return Decision(BLOCK, 'child_not_in_group')
            if request.child_id in group.revoked_children:
                return Decision(BLOCK, 'child_authorization_revoked')
            expected = {**group.shared_arguments, **group.child_arguments[request.child_id]}
            missing_fields = set(schema.get('argument_bindings', {})) - set(expected)
            if missing_fields:
                return Decision(ASK, 'group_child_binding_incomplete', tuple(sorted(missing_fields)))
            if canonical(expected) != canonical(request.arguments):
                return Decision(BLOCK, 'group_child_binding_mismatch', proof={'expected_arguments': expected})
            group_proof_atoms = set(schema.get('proof_atoms', [])) - {schema.get('consumption_atom')}
            missing = [atom for atom in group_proof_atoms if atom not in self.bindings or not self.bindings[atom].active or (not self.bindings[atom].authorized)]
            if missing:
                return Decision(ASK, 'group_consequence_closure_required', tuple(sorted(missing)))
            semantic_key = canonical({'group': request.group_id, 'grant_version': group.grant_version, 'member_version': group.member_versions[request.child_id], 'shared_version': group.shared_version, 'child': request.child_id, 'child_version': group.child_versions[request.child_id], 'schema': request.schema_id, 'arguments': request.arguments})
            self.remaining_budget[semantic_key] = group.remaining_budget[request.child_id]
            proof = {'schema': 'acg-proof', 'path': 'group_projection', 'group_id': group.group_id, 'grant_version': group.grant_version, 'member_version': group.member_versions[request.child_id], 'shared_version': group.shared_version, 'child_id': request.child_id, 'child_version': group.child_versions[request.child_id], 'membership': list(group.members), 'evidence_ids': list(group.evidence_ids), 'arguments': copy.deepcopy(request.arguments), 'policy_results': copy.deepcopy(policy_results)}
            proof['effect_schema'] = request.schema_id
            proof['binding_versions'] = self._proof_closure(self._policy_atoms(schema) | group_proof_atoms, {})
            return self._new_reservation(semantic_key=semantic_key, proof=proof, group_ref=(group.group_id, request.child_id))
        expected_keys = set(schema.get('argument_bindings', {}))
        if set(request.arguments) != expected_keys:
            return Decision(BLOCK, 'effect_argument_surface_mismatch')
        repair: list[str] = []
        versions: dict[str, int] = {}
        proof_nodes: dict[str, Any] = {}
        authority_instances: list[str] = []
        checked_atoms: set[str] = set()
        for argument_name, atom_id_value in schema.get('argument_bindings', {}).items():
            atom_id = str(atom_id_value)
            binding = self.bindings.get(atom_id)
            if binding is None or not binding.active or (not binding.authorized):
                repair.append(atom_id)
                continue
            if canonical(binding.value) != canonical(request.arguments[argument_name]):
                return Decision(BLOCK, 'effect_binding_mismatch', proof={'argument': argument_name, 'bound_atom': atom_id})
            versions[atom_id] = binding.version
            authority_instances.extend(binding.authority_sources)
            checked_atoms.add(atom_id)
            proof_nodes[atom_id] = {'kind': binding.kind, 'version': binding.version, 'parents': list(binding.parents), 'rule_id': binding.rule_id, 'evidence_ids': list(binding.evidence_ids)}
        for atom_id_value in schema.get('proof_atoms', []):
            atom_id = str(atom_id_value)
            if atom_id in checked_atoms:
                continue
            binding = self.bindings.get(atom_id)
            if binding is None or not binding.active or (not binding.authorized):
                repair.append(atom_id)
                continue
            versions[atom_id] = binding.version
            authority_instances.extend(binding.authority_sources)
            proof_nodes[atom_id] = {'kind': binding.kind, 'version': binding.version, 'parents': list(binding.parents), 'rule_id': binding.rule_id, 'evidence_ids': list(binding.evidence_ids), 'proof_only': True}
        if repair:
            frontier = self.minimal_repair_frontier(set(repair))
            return Decision(ASK, 'minimal_authorization_repair_required', tuple(sorted(frontier)))
        action_hash = hashlib.sha256(canonical({'schema': request.schema_id, 'arguments': request.arguments}).encode('utf-8')).hexdigest()
        consumption_atom = schema.get('consumption_atom')
        if consumption_atom is not None:
            lease = self.bindings.get(str(consumption_atom))
            if lease is None or not lease.active or (not lease.authorized):
                return Decision(ASK, 'minimal_authorization_repair_required', (str(consumption_atom),))
            if schema.get('consumption_binding') == 'exact_arguments' and canonical(lease.value) != canonical({'arguments': request.arguments}):
                return Decision(ASK, 'minimal_authorization_repair_required', (str(consumption_atom),))
            budget_sources = list(lease.authority_sources)
        else:
            budget_sources = authority_instances
        semantic_key = canonical({'authority_instances': sorted(set(budget_sources)), 'schema': request.schema_id, 'arguments': request.arguments if consumption_atom is None else None})
        default_budget = int(schema.get('budget', 1))
        self.remaining_budget.setdefault(semantic_key, default_budget)
        versions = self._proof_closure(set(versions) | self._policy_atoms(schema), proof_nodes)
        proof = {'schema': 'acg-proof', 'path': 'commitment_derivation_closure', 'action_sha256': action_hash, 'arguments': copy.deepcopy(request.arguments), 'effect_schema': request.schema_id, 'binding_versions': versions, 'proof_nodes': proof_nodes, 'authority_instances': sorted(set(authority_instances)), 'policy_results': copy.deepcopy(policy_results)}
        return self._new_reservation(semantic_key=semantic_key, proof=proof, group_ref=None)

    @staticmethod
    def _policy_atoms(schema: Mapping[str, Any]) -> set[str]:
        atoms: set[str] = set()
        for policy in schema.get('policies', []):
            atoms |= expression_atoms(policy.get('expression', policy) if isinstance(policy, Mapping) else policy)
        return atoms

    def _proof_closure(self, roots: set[str], nodes: dict[str, Any]) -> dict[str, int]:
        versions: dict[str, int] = {}
        frontier = list(roots)
        while frontier:
            atom = frontier.pop()
            if atom in versions:
                continue
            binding = self.bindings.get(atom)
            if binding is None or not binding.active:
                continue
            versions[atom] = binding.version
            nodes.setdefault(atom, {'kind': binding.kind, 'version': binding.version, 'parents': list(binding.parents), 'rule_id': binding.rule_id, 'evidence_ids': list(binding.evidence_ids), 'ancestor': True})
            frontier.extend(binding.parents)
        return versions

    def abort(self, reservation_id: str) -> None:
        reservation = self.reservations.pop(reservation_id)
        key = reservation['semantic_key']
        self.reserved_budget[key] -= 1

    def commit(self, reservation_id: str) -> Decision:
        reservation = self.reservations.pop(reservation_id)
        key = reservation['semantic_key']
        self.reserved_budget[key] -= 1
        proof = reservation['proof']
        group_ref = reservation['group_ref']
        if group_ref is not None:
            group_id, child_id = group_ref
            group = self.groups.get(group_id)
            if group is None or group.grant_version != proof['grant_version'] or group.member_versions.get(child_id) != proof['member_version'] or (group.shared_version != proof['shared_version']) or (group.child_versions.get(child_id) != proof['child_version']):
                return Decision(BLOCK, 'group_proof_stale', proof=proof)
            if child_id in group.revoked_children:
                return Decision(BLOCK, 'child_authorization_revoked', proof=proof)
        for atom_id, version in proof.get('binding_versions', {}).items():
            binding = self.bindings.get(atom_id)
            if binding is None or not binding.active or binding.version != version:
                return Decision(BLOCK, 'closure_proof_stale', proof=proof)
        policy_decision, _ = self._evaluate_policies(self._effect_schema(proof['effect_schema']), proof['arguments'])
        if policy_decision is not None:
            return Decision(BLOCK, 'commit_policy_revalidation_failed', proof=proof)
        if self.remaining_budget.get(key, 0) <= 0:
            return Decision(BLOCK, 'authorization_budget_exhausted', proof=proof)
        self.remaining_budget[key] -= 1
        if group_ref is not None:
            group_id, child_id = group_ref
            self.groups[group_id].remaining_budget[child_id] -= 1
        committed = copy.deepcopy(proof)
        committed['consumption'] = {'semantic_key_sha256': hashlib.sha256(key.encode('utf-8')).hexdigest(), 'remaining_budget': self.remaining_budget[key]}
        return Decision(AUTHORIZE, 'closure_proof_committed', proof=committed)
__all__ = ['ASK', 'AUTHORIZE', 'BLOCK', 'SATISFIED', 'REFUTED', 'UNKNOWN', 'AuthorizationClosureEngine', 'Decision', 'EffectRequest']
