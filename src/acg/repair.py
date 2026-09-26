from __future__ import annotations
import copy
import json
from typing import Any, Mapping
from .mediator import canonical

def leaves(repair: Mapping[str, Any]):
    nested = repair.get('candidates')
    if isinstance(nested, list) and nested:
        for row in nested:
            if isinstance(row, Mapping) and isinstance(row.get('repair'), Mapping):
                yield from leaves(row['repair'])
    else:
        yield repair

def semantic_repair(repair: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(repair))
    if isinstance(result.get('candidates'), list):
        result['candidates'] = [{**{k: copy.deepcopy(v) for k, v in row.items() if k not in {'candidate_id', 'repair'}}, 'repair': semantic_repair(row['repair'])} for row in result['candidates']]
    return result

def questions(repair: Mapping[str, Any]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for leaf in leaves(repair):
        for row in leaf.get('context_questions') or []:
            key = canonical(row)
            if key not in seen:
                seen.add(key)
                output.append(copy.deepcopy(dict(row)))
    return output

def render_repair(repair: Mapping[str, Any]) -> str:
    qs = questions(repair)
    required = sorted({str(a) for leaf in leaves(repair) for a in leaf.get('required_witness_atoms', [])})
    producers = sorted({str(name) for leaf in leaves(repair) for names in (leaf.get('native_witness_tools') or {}).values() for name in names})
    lines = []
    if qs:
        lines.append('ONE DETAIL NEEDED BEFORE AUTHORIZATION')
        actions = [row.get('action') for row in repair.get('candidates', []) if row.get('action')]
        if actions:
            lines.append('This question applies only to these proposed actions:')
            lines.extend(('- ' + canonical(action) for action in actions))
        for row in qs:
            lines.append(str(row['question']))
            if row.get('options'):
                lines.append('Choose one: ' + ', '.join((str(v) for v in row['options'])) + '.')
                lines.append(f'Reply exactly {row['atom']}=<one choice>. Use other if listed and no specific reason fits.')
        lines.append('Your answer supplies context only. The exact action still requires a separate CONFIRM.')
        if actions:
            lines.append('Different answers for different actions require separate proposals.')
    if producers and (not qs):
        lines.append(f'AUTHORITATIVE INFORMATION NEEDED: {', '.join(required)}. Use one of these read-only tools: {', '.join(producers)}.')
    if not lines:
        lines.append(f'AUTHORIZATION CANNOT PROCEED YET. Missing typed context: {', '.join(required)}. Do not repeat the same write call without new evidence.')
    return '\n'.join(lines)

def context_answer(text: str, repair: Mapping[str, Any], prompts: Mapping[str, Any]) -> dict[str, Any]:
    qs = questions(repair)
    by_atom = {}
    for q in qs:
        atom = str(q['atom'])
        if atom in by_atom and canonical(by_atom[atom]) != canonical(q):
            return {}
        by_atom[atom] = q
    result = {}
    for line in text.strip().splitlines():
        line = line.strip().rstrip('.')
        if '=' in line:
            atom, value = (part.strip() for part in line.split('=', 1))
        elif len(by_atom) == 1 and len(text.strip().splitlines()) == 1:
            atom, value = (next(iter(by_atom)), line)
        else:
            continue
        if atom not in by_atom:
            continue
        matches = [v for v in by_atom[atom].get('options', []) if str(v).casefold() == value.casefold()]
        if len(matches) != 1:
            continue
        option = str(matches[0])
        values = prompts.get(atom, {}).get('option_values', {})
        value = copy.deepcopy(values.get(option, option))
        if atom in result and result[atom] != value:
            return {}
        result[atom] = value
    return result

def rejection_details(engine, request, atom_names: Mapping[str, str], proof: Mapping[str, Any]) -> dict[str, Any]:
    failed = {r['policy_id'] for r in proof.get('policy_results', []) if r.get('state') == 'refuted'}
    schema = engine.spec['effects'][request.schema_id]
    from .core import expression_atoms
    roots = set()
    conditions = []
    for index, policy in enumerate(schema.get('policies', [])):
        name = str(policy.get('id', index)) if isinstance(policy, Mapping) else str(index)
        if name in failed:
            expression = policy.get('expression', policy) if isinstance(policy, Mapping) else policy
            roots |= expression_atoms(expression)
            conditions.append(name)
    frontier = list(sorted(roots))
    seen = set()
    facts = {}
    while frontier and len(seen) < 128:
        atom = frontier.pop(0)
        if atom in seen:
            continue
        seen.add(atom)
        binding = engine.bindings.get(atom)
        if binding is None or not binding.active:
            continue
        value = binding.value
        scalar = value is None or isinstance(value, (bool, int, float, str))
        small = isinstance(value, (dict, list)) and len(canonical(value)) <= 450
        if (scalar or small) and len(facts) < 24:
            facts[atom_names.get(atom, atom)] = copy.deepcopy(value)
        frontier.extend(binding.parents)
    return {'failed_conditions': sorted(conditions), 'computed_candidate_facts': facts}

def render_rejection(details: Mapping[str, Any]) -> str:
    if details.get('repair_guidance'):
        facts = {k: v for k, v in details.items() if k != 'repair_guidance'}
        return 'I COULD NOT EXECUTE THIS ACTION. The following condition was not satisfied:\n' + json.dumps(facts, ensure_ascii=False, sort_keys=True, indent=2) + '\n' + '\n'.join(details['repair_guidance']) + '\nThis action made no change; earlier completed actions are not undone. The agent can propose a corrected action using the observed records and your request. It must pass the same policy checks and receive a new exact confirmation before execution. If no policy-compliant correction meets your request, no action will be taken.'
    return 'I COULD NOT EXECUTE THIS ACTION. The following condition was not satisfied:\n' + json.dumps(dict(details), ensure_ascii=False, sort_keys=True, indent=2) + '\nThis action made no change; earlier completed actions are not undone. I cannot waive policy or silently increase your budget. Confirming the same unchanged action will not resolve this condition. If the exact combination exceeds your constraints, we can stop this request without executing it. Would you like to stop, or consider a different option within your constraints?'
