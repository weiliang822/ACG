from __future__ import annotations
import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from .core import EffectRequest
_PATH_TOKEN = re.compile('\\.([A-Za-z_][A-Za-z0-9_-]*)|\\[(\\d+|\\*)\\]')
_TEMPLATE_TOKEN = re.compile('\\{call\\.([A-Za-z_][A-Za-z0-9_-]*)\\}')

def extract_path(document: Any, path: str) -> Any:
    if not path.startswith('$'):
        raise ValueError(f'path must start with $: {path}')
    position = 1
    values = [document]
    while position < len(path):
        match = _PATH_TOKEN.match(path, position)
        if match is None:
            raise ValueError(f'unsupported path syntax at {path[position:]} in {path}')
        key, index = match.groups()
        next_values: list[Any] = []
        for value in values:
            if key is not None:
                if not isinstance(value, Mapping) or key not in value:
                    raise KeyError(f'missing key {key} in {path}')
                next_values.append(value[key])
            elif index == '*':
                if not isinstance(value, list):
                    raise TypeError(f'wildcard requires a list in {path}')
                next_values.extend(value)
            else:
                if not isinstance(value, list):
                    raise TypeError(f'index requires a list in {path}')
                next_values.append(value[int(index)])
        values = next_values
        position = match.end()
    if len(values) == 1:
        return copy.deepcopy(values[0])
    return copy.deepcopy(values)

def render_atom_template(template: str, call_arguments: Mapping[str, Any]) -> str:

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in call_arguments:
            raise KeyError(f'atom template references missing call argument: {key}')
        value = call_arguments[key]
        if isinstance(value, (dict, list)):
            raise ValueError('atom template substitutions must be scalar')
        return str(value)
    rendered = _TEMPLATE_TOKEN.sub(replace, template)
    if '{' in rendered or '}' in rendered:
        raise ValueError(f'unsupported atom template syntax: {template}')
    return rendered

@dataclass(frozen=True)
class CandidateCompilation:
    decision: str
    reason: str
    request: EffectRequest | None = None
    effect_spec: str | None = None
    details: dict[str, Any] | None = None

@dataclass(frozen=True)
class StatePatch:
    collection: str
    key: str
    value: Any

class ManifestCompiler:

    def __init__(self, manifest: Mapping[str, Any]):
        self.manifest = copy.deepcopy(dict(manifest))
        self._validate()

    def _validate(self) -> None:
        tools = self.manifest.get('tools')
        if not isinstance(tools, Mapping):
            raise ValueError('manifest.tools must be an object')
        for name, entry in tools.items():
            if not isinstance(entry, Mapping):
                raise ValueError(f'tool entry must be an object: {name}')
            kind = entry.get('kind')
            if kind not in {'effect', 'witness', 'read'}:
                raise ValueError(f'unknown manifest tool kind: {kind}')
            mutates = entry.get('mutates_state')
            if not isinstance(mutates, bool):
                raise ValueError(f'mutates_state must be boolean: {name}')
            if kind == 'effect':
                if not mutates or not isinstance(entry.get('effect_schema'), str):
                    raise ValueError(f'effect entries need mutation and schema: {name}')
                effect_spec = entry.get('effect_spec')
                if effect_spec is not None and (not isinstance(effect_spec, str) or not effect_spec or Path(effect_spec).is_absolute() or ('..' in Path(effect_spec).parts)):
                    raise ValueError(f'effect_spec must be a safe relative path: {name}')
                bindings = entry.get('argument_bindings')
                if not isinstance(bindings, Mapping):
                    raise ValueError(f'effect argument_bindings missing: {name}')
                for path in bindings.values():
                    extract_path({}, str(path)) if str(path) == '$' else self._validate_path(str(path))
                contracts = entry.get('argument_contracts', [])
                if not isinstance(contracts, list):
                    raise ValueError(f'argument_contracts must be a list: {name}')
                for contract in contracts:
                    if not isinstance(contract, Mapping):
                        raise ValueError(f'argument contract must be an object: {name}')
                    self._validate_path(str(contract.get('path')))
                    if contract.get('kind') not in {'nonempty_scalar'}:
                        raise ValueError(f'unsupported argument contract kind: {name}')
            elif kind == 'witness':
                if mutates:
                    raise ValueError(f'witness entries cannot mutate: {name}')
                bindings = entry.get('bindings')
                if not isinstance(bindings, list) or not bindings:
                    raise ValueError(f'witness bindings missing: {name}')
                for binding in bindings:
                    if not isinstance(binding, Mapping):
                        raise ValueError(f'witness binding must be an object: {name}')
                    if not isinstance(binding.get('atom_template'), str):
                        raise ValueError(f'atom_template missing: {name}')
                    self._validate_path(str(binding.get('value_path')))
            elif mutates:
                raise ValueError(f'read entries cannot mutate: {name}')
            patches = entry.get('state_patches', [])
            if not isinstance(patches, list):
                raise ValueError(f'state_patches must be a list: {name}')
            for patch in patches:
                if not isinstance(patch, Mapping):
                    raise ValueError(f'state patch must be an object: {name}')
                collection = patch.get('collection')
                if not isinstance(collection, str) or not collection:
                    raise ValueError(f'state patch collection missing: {name}')
                self._validate_path(str(patch.get('key_path')))
                self._validate_path(str(patch.get('value_path')))

    @staticmethod
    def _validate_path(path: str) -> None:
        if not path.startswith('$'):
            raise ValueError(f'path must start with $: {path}')
        position = 1
        while position < len(path):
            match = _PATH_TOKEN.match(path, position)
            if match is None:
                raise ValueError(f'unsupported path syntax: {path}')
            position = match.end()

    def compile_candidate(self, *, tool_name: str, arguments: Mapping[str, Any], runtime_mutation_signal: bool) -> CandidateCompilation:
        entry = self.manifest['tools'].get(tool_name)
        if entry is None:
            if runtime_mutation_signal:
                return CandidateCompilation('block', 'unmanifested_mutation')
            return CandidateCompilation('passthrough', 'unmanifested_nonmutation')
        if runtime_mutation_signal != bool(entry['mutates_state']):
            return CandidateCompilation('block', 'mutation_metadata_manifest_mismatch')
        if entry['kind'] != 'effect':
            return CandidateCompilation('passthrough', f'manifested_{entry['kind']}')
        invalid_paths: list[str] = []
        for contract in entry.get('argument_contracts', []):
            path = str(contract['path'])
            try:
                value = extract_path(arguments, path)
            except (KeyError, IndexError, TypeError, ValueError):
                invalid_paths.append(path)
                continue
            values = value if isinstance(value, list) else [value]
            if not values or any((isinstance(item, (dict, list)) for item in values)) or any((item is None or (isinstance(item, str) and (not item.strip())) for item in values)):
                invalid_paths.append(path)
        if invalid_paths:
            return CandidateCompilation('block', 'candidate_argument_contract_failed', details={'invalid_paths': sorted(set(invalid_paths))})
        effect_arguments = {str(effect_field): extract_path(arguments, str(path)) for effect_field, path in entry['argument_bindings'].items()}
        return CandidateCompilation('effect', 'compiled_from_manifest', EffectRequest(str(entry['effect_schema']), effect_arguments), str(entry['effect_spec']) if entry.get('effect_spec') else None)

    def compile_state_patches(self, *, tool_name: str, result: Any) -> tuple[StatePatch, ...]:
        entry = self.manifest['tools'].get(tool_name)
        if entry is None:
            return ()
        patches: list[StatePatch] = []
        for patch in entry.get('state_patches', []):
            key = extract_path(result, str(patch['key_path']))
            if isinstance(key, (dict, list)) or key is None:
                raise ValueError('state patch key must be a non-null scalar')
            patches.append(StatePatch(collection=str(patch['collection']), key=str(key), value=extract_path(result, str(patch['value_path']))))
        return tuple(patches)

    def compile_witness_event(self, *, tool_name: str, call_arguments: Mapping[str, Any], result: Any, evidence_id: str) -> dict[str, Any]:
        entry = self.manifest['tools'].get(tool_name)
        if entry is None or entry['kind'] != 'witness':
            raise ValueError('tool is not a manifested witness source')
        fields: dict[str, Any] = {}
        for binding in entry['bindings']:
            atom_id = render_atom_template(str(binding['atom_template']), call_arguments)
            if atom_id in fields:
                raise ValueError(f'duplicate compiled witness atom: {atom_id}')
            fields[atom_id] = extract_path(result, str(binding['value_path']))
        return {'event_type': 'witness', 'fields': fields, 'evidence_ids': [str(evidence_id)]}
__all__ = ['CandidateCompilation', 'ManifestCompiler', 'StatePatch', 'extract_path', 'render_atom_template']
