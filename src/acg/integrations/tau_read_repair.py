from __future__ import annotations
import copy
import hashlib
from typing import Mapping
from ..manifest import extract_path
from ..mediator import canonical
from ..repair import leaves, questions
from .tau_tooling import is_mutating_tool

def plan_read(repair, plans, tool_manifest, context, attempted):
    if questions(repair):
        return None
    allowed = {name for leaf in leaves(repair) for names in (leaf.get('native_witness_tools') or {}).values() for name in names}
    for name in sorted(allowed, key=lambda n: (plans.get(n, {}).get('priority', 100), n)):
        entry = tool_manifest.get('tools', {}).get(name, {})
        if entry.get('kind') != 'witness' or entry.get('mutates_state') is not False:
            raise ValueError('repair producer must be a declared nonmutating witness')
        plan = plans.get(name)
        if not isinstance(plan, Mapping):
            continue
        try:
            values = extract_path(context, plan['foreach']) if plan.get('foreach') else [None]
            values = values if isinstance(values, list) else [values]
        except (KeyError, TypeError, IndexError):
            continue
        for value in values:
            selection = plan.get('select_members')
            if selection:
                requested = context['arguments'].get(selection['argument']) or []
                if not isinstance(value, Mapping) or value.get(selection['field']) not in requested:
                    continue
            view = {**context, 'item': value}
            arguments = {}
            for arg, sources in plan.get('arguments', {}).items():
                for source in sources if isinstance(sources, list) else [sources]:
                    try:
                        resolved = extract_path(view, source)
                    except (KeyError, TypeError, IndexError):
                        continue
                    if resolved is not None and (not isinstance(resolved, (list, dict))) and str(resolved).strip():
                        arguments[arg] = resolved
                        break
            if not arguments or set(arguments) != set(plan.get('arguments', {})):
                continue
            key = canonical({'request_id': context['request_id'], 'write': context['write'], 'read': name, 'arguments': arguments})
            if key not in attempted:
                return {'tool': name, 'arguments': arguments, 'attempt_key': key}
    return None

def repair_read_message(agent, outcome, candidate, observed_record):
    from tau2.data_model.message import AssistantMessage, ToolCall
    pending = agent.adapter.pending_repair
    if pending is None or not outcome.repair:
        return None
    plans = agent.recovery_manifest.get('witness_read_plans') or {}
    attempted = agent._repair_read_attempts
    for call in candidate.tool_calls or []:
        if agent.tool_manifest.manifest['tools'].get(call.name, {}).get('kind') != 'effect':
            continue
        if outcome.selected_candidate_id is not None and str(call.id) != str(outcome.selected_candidate_id):
            continue
        context = {'arguments': copy.deepcopy(call.arguments), 'write': {'tool': call.name, 'arguments': copy.deepcopy(call.arguments)}, 'request_id': call.id, 'identity': agent.presented_user_id, 'record': observed_record(call)}
        read = plan_read(outcome.repair, plans, agent.tool_manifest.manifest, context, attempted)
        if read is None:
            continue
        if hasattr(agent, 'tools'):
            tools = [t for t in agent.tools if t.name == read['tool']]
            if len(tools) != 1 or is_mutating_tool(tools[0]):
                raise RuntimeError('read repair does not match a nonmutating native tool')
        attempted.add(read['attempt_key'])
        read_id = 'acg_read_' + hashlib.sha256(read['attempt_key'].encode()).hexdigest()[:24]
        event = {'decision': 'read', 'reason': 'declared_witness_read_dispatched', 'producer': read['tool'], 'arguments': copy.deepcopy(read['arguments']), 'source_write_call_id': call.id, 'authorization_granted': False}
        return AssistantMessage.text(None, tool_calls=[ToolCall(id=read_id, name=read['tool'], arguments=read['arguments'], requestor='assistant')], cost=candidate.cost, usage=candidate.usage, generation_time_seconds=candidate.generation_time_seconds, raw_data={'provider_response': candidate.raw_data, 'acg': [*outcome.audit_events, event]})
    return None
