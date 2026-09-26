from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping
from tau2.agent.llm_agent import LLMAgent, LLMAgentState
from tau2.data_model.message import AssistantMessage, MultiToolMessage, ToolCall, ToolMessage, UserMessage
from tau2.utils.utils import get_now
from ..adapter import AuthorizationAdapter, ASK_CONFIRMATION, BLOCK, NativeCallCandidate, NativeCandidateEnvelope, PASSTHROUGH, REPAIR_WITNESS, REPLAY
from ..domains.airline_context import propose_cancellation_reason, propose_time_constraints
from ..domains.airline_witnesses import project_airline_witnesses
from ..manifest import ManifestCompiler
from ..mediator import canonical
from .tau_tooling import is_mutating_tool
from .tau_read_repair import repair_read_message
from ..airline_spec import TOOLS, RECOVERY, EFFECTS
NORMALIZATION_SCHEMA = 'acg-half-duplex-tool-response-normalization'

def _decode(content: str | None) -> Any:
    if content is None:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return content.strip()

def _call_bytes(call: ToolCall) -> bytes:
    return canonical(call.model_dump(mode='json')).encode('utf-8')

def _message_bytes(message: AssistantMessage) -> bytes:
    return canonical(message.model_dump(mode='json')).encode('utf-8')

def normalize_half_duplex_assistant_message(message: AssistantMessage) -> AssistantMessage:
    if not message.tool_calls or not message.has_text_content():
        return message
    content = message.content or ''
    raw_data: dict[str, Any] = dict(message.raw_data or {})
    raw_data['half_duplex_normalization'] = {'schema': NORMALIZATION_SCHEMA, 'applied': True, 'reason': 'provider_returned_text_and_tool_calls', 'removed_text_sha256': hashlib.sha256(content.encode('utf-8')).hexdigest(), 'tool_call_count': len(message.tool_calls), 'tool_calls_unchanged': True}
    return message.model_copy(update={'content': None, 'raw_data': raw_data})

class HalfDuplexNormalizedLLMAgent(LLMAgent):

    def generate_next_message(self, message, state: LLMAgentState):
        candidate = normalize_half_duplex_assistant_message(self._generate_next_message(message, state))
        state.messages.append(candidate)
        return (candidate, state)

class TauAirlineACGAgent(HalfDuplexNormalizedLLMAgent):

    def __init__(self, tools, domain_policy: str, llm: str, llm_args: dict | None, db_path: Path):
        super().__init__(tools=tools, domain_policy=domain_policy, llm=llm, llm_args=llm_args)
        self.db_path = db_path
        self.tool_manifest = ManifestCompiler(TOOLS)
        self.recovery_manifest = copy.deepcopy(RECOVERY)
        self.mutating_tool_names = {tool.name for tool in tools if is_mutating_tool(tool)}
        self._reset_runtime()

    def _load_spec(self, profile: Mapping[str, Any], _compilation) -> Mapping[str, Any]:
        return copy.deepcopy(EFFECTS[str(profile['effect_spec'])])

    def _new_adapter(self) -> AuthorizationAdapter:
        return AuthorizationAdapter(tool_manifest=self.tool_manifest.manifest, recovery_manifest=self.recovery_manifest, effect_spec_loader=self._load_spec, state_cache=self.state_cache, witness_fields=self.global_witness_fields, witness_evidence=tuple(self.witness_evidence), witness_projector=self._project_session_candidate)

    def _project_session_candidate(self, candidate):
        return project_airline_witnesses(db=self.state_cache, required_witnesses=list(candidate.effect_spec.get('execution_metadata', {}).get('required_witnesses', [])), arguments=candidate.request.arguments, context_commitments=candidate.context_commitments, committed_receipts=self.committed_receipts).fields

    def _reset_runtime(self) -> None:
        db = json.loads(self.db_path.read_text(encoding='utf-8'))
        self.state_cache = {key: copy.deepcopy(db[key]) for key in ('flights', 'users', 'reservations')}
        self.global_witness_fields: dict[str, Any] = {}
        self.witness_evidence: list[str] = []
        self.presented_user_id: str | None = None
        self.observed_reservation_ids: list[str] = []
        self.user_text_history: list[str] = []
        self.committed_receipts: set[tuple[str, str]] = set()
        self.executed_by_call_id: dict[str, tuple[str, str]] = {}
        self.adapter = self._new_adapter()
        self.pending_candidate: AssistantMessage | None = None
        self.pending_calls: dict[str, ToolCall] = {}
        self.pending_repair_candidate: AssistantMessage | None = None
        self.pending_repair_calls: dict[str, ToolCall] = {}
        self._repair_read_attempts: set[str] = set()

    def get_init_state(self, message_history=None) -> LLMAgentState:
        self._reset_runtime()
        return super().get_init_state(message_history)

    @staticmethod
    def _find_call(state: LLMAgentState, call_id: str) -> ToolCall | None:
        for prior in reversed(state.messages):
            if isinstance(prior, AssistantMessage):
                for call in prior.tool_calls or []:
                    if call.id == call_id:
                        return call
        return None

    def _observe_one_tool(self, message: ToolMessage, state: LLMAgentState) -> None:
        if message.error:
            return
        call = self._find_call(state, message.id)
        if call is None:
            return
        value = _decode(message.content)
        entry = self.tool_manifest.manifest['tools'].get(call.name)
        if entry is not None:
            for patch in self.tool_manifest.compile_state_patches(tool_name=call.name, result=value):
                collection = self.state_cache.get(patch.collection)
                if isinstance(collection, dict):
                    collection[patch.key] = copy.deepcopy(patch.value)
            if entry['kind'] == 'witness':
                event = self.tool_manifest.compile_witness_event(tool_name=call.name, call_arguments=call.arguments, result=value, evidence_id=f'tool-result:{message.id}')
                self.global_witness_fields.update(copy.deepcopy(event['fields']))
                self.witness_evidence.extend(event['evidence_ids'])
        if call.name == 'get_user_details' and isinstance(value, Mapping):
            if value.get('user_id') is not None:
                self.presented_user_id = str(value['user_id'])
        if call.name == 'get_reservation_details' and isinstance(value, Mapping):
            if value.get('reservation_id') is not None:
                identifier = str(value['reservation_id'])
                if identifier not in self.observed_reservation_ids:
                    self.observed_reservation_ids.append(identifier)
        executed = self.executed_by_call_id.pop(call.id, None)
        if executed is not None:
            schema_id, reservation_id = executed
            if reservation_id:
                self.committed_receipts.add((schema_id, reservation_id))

    def _observe_tool(self, message, state: LLMAgentState) -> None:
        if isinstance(message, ToolMessage):
            self._observe_one_tool(message, state)
        elif isinstance(message, MultiToolMessage):
            for child in message.tool_messages:
                self._observe_one_tool(child, state)

    def _context_for(self, tool_name: str, arguments: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
        allowed = set(spec.get('execution_metadata', {}).get('context_commitments', []))
        context: dict[str, Any] = {}
        if 'presented_user_id' in allowed and self.presented_user_id is not None:
            context['presented_user_id'] = self.presented_user_id
        history = '\n'.join(self.user_text_history[-12:]).lower()
        if 'cancellation_reason' in allowed:
            proposed = propose_cancellation_reason(self.user_text_history[-12:])
            if proposed is not None:
                context['cancellation_reason'] = proposed
        if 'time_constraints' in allowed:
            constraints = propose_time_constraints(self.user_text_history[-12:])
            if constraints:
                context['time_constraints'] = constraints
        if 'compensation_requested' in allowed and any((token in history for token in ('compensation', 'certificate', 'travel credit'))):
            context['compensation_requested'] = True
        if 'compensation_reservation_id' in allowed and self.observed_reservation_ids:
            context['compensation_reservation_id'] = self.observed_reservation_ids[-1]
        return context

    def _native_candidate(self, call: ToolCall, index: int) -> NativeCallCandidate:
        entry = self.tool_manifest.manifest['tools'][call.name]
        spec = copy.deepcopy(EFFECTS[str(entry['effect_spec'])])
        context = self._context_for(call.name, call.arguments, spec)
        context = {**self.adapter.context_proposals(call.name, call.arguments), **context}
        projection = project_airline_witnesses(db=self.state_cache, required_witnesses=list(spec.get('execution_metadata', {}).get('required_witnesses', [])), arguments=call.arguments, context_commitments=context, committed_receipts=self.committed_receipts)
        return NativeCallCandidate(candidate_id=str(call.id or f'candidate-{index}'), tool_name=call.name, arguments=copy.deepcopy(call.arguments), runtime_mutation_signal=True, replay_bytes=_call_bytes(call), context_commitments=context, projected_witness_fields=projection.fields)

    @staticmethod
    def _latest_visible_text(state: LLMAgentState) -> str:
        for prior in reversed(state.messages):
            if isinstance(prior, AssistantMessage) and isinstance(prior.content, str):
                return prior.content
        return ''

    def _try_confirmation(self, message, state: LLMAgentState):
        if self.adapter.pending is None:
            return None
        disclosure = self.adapter.pending.disclosure
        if not isinstance(message, UserMessage) or message.is_tool_call():
            return None
        exact = message.content == 'CONFIRM'
        outcome = self.adapter.handle_confirmation(proposal_id=self.adapter.pending.proposal_id, user_text=message.content, latest_visible_disclosure=self._latest_visible_text(state))
        if not exact:
            self.pending_candidate = None
            self.pending_calls = {}
            return None
        if outcome.decision != REPLAY or outcome.selected_candidate_id is None:
            replacement = AssistantMessage.text('The trusted authorization could not be committed.', raw_data={'acg': list(outcome.audit_events)})
            state.messages.append(message)
            state.messages.append(replacement)
            self.pending_candidate = None
            self.pending_calls = {}
            return (replacement, state)
        selected = self.pending_calls[outcome.selected_candidate_id]
        if outcome.outbound_bytes != _call_bytes(selected):
            raise RuntimeError('generic adapter replay bytes differ from selected Tau call')
        raw_data = dict((self.pending_candidate.raw_data if self.pending_candidate else None) or {})
        raw_data['acg'] = list(outcome.audit_events)
        replay = AssistantMessage.text(None, tool_calls=[selected], cost=self.pending_candidate.cost if self.pending_candidate else None, usage=self.pending_candidate.usage if self.pending_candidate else None, raw_data=raw_data, generation_time_seconds=self.pending_candidate.generation_time_seconds if self.pending_candidate else None).model_copy(update={'timestamp': get_now()})
        entry = self.tool_manifest.manifest['tools'][selected.name]
        self.executed_by_call_id[selected.id] = (str(entry['effect_schema']), str(selected.arguments.get('reservation_id', '')))
        state.messages.append(message)
        state.messages.append(replay)
        self.pending_candidate = None
        self.pending_calls = {}
        messages = state.messages
        if len(messages) >= 3 and isinstance(messages[-3], AssistantMessage) and (messages[-3].content == disclosure) and isinstance(messages[-2], UserMessage) and (messages[-2].content == 'CONFIRM') and (messages[-1] is replay):
            compacted_raw = copy.deepcopy(dict(replay.raw_data or {}))
            compacted_raw['history_compaction'] = {'mediator_turns_hidden_from_future_agent_prompt': 2, 'user_visible_transcript_preserved_by_orchestrator': True}
            replay = replay.model_copy(update={'raw_data': compacted_raw})
            messages[-3:] = [replay]
        return (replay, state)

    def _repair_read_message(self, outcome, candidate):

        def observed_record(call):
            identifier = str(call.arguments.get('reservation_id', ''))
            if identifier not in self.observed_reservation_ids:
                return {}
            return copy.deepcopy(self.state_cache['reservations'].get(identifier) or {})
        return repair_read_message(self, outcome, candidate, observed_record)

    def _clear_pending_repair(self) -> None:
        self.pending_repair_candidate = None
        self.pending_repair_calls = {}
        self.adapter.cancel_pending_repair()

    def _try_pending_repair_replay(self, message, state: LLMAgentState):
        candidate = self.pending_repair_candidate
        if candidate is None or self.adapter.pending_repair is None:
            return None
        calls = [call for call in candidate.tool_calls or [] if str(call.id) in self.pending_repair_calls]
        native_calls = tuple((self._native_candidate(call, index) for index, call in enumerate(calls)))
        envelope = NativeCandidateEnvelope(_message_bytes(candidate), native_calls)
        if not self.adapter.pending_repair_observation_changed(envelope):
            return None
        outcome = self.adapter.retry_pending_repair(envelope)
        raw_data = {'provider_response': candidate.raw_data, 'acg': list(outcome.audit_events)}
        if outcome.decision == ASK_CONFIRMATION:
            self.pending_candidate = candidate
            self.pending_calls = {str(call.id): call for call in calls}
            self.pending_repair_candidate = None
            self.pending_repair_calls = {}
            replacement = AssistantMessage.text(outcome.disclosure, cost=candidate.cost, usage=candidate.usage, raw_data=raw_data, generation_time_seconds=candidate.generation_time_seconds)
        elif outcome.decision == REPAIR_WITNESS:
            replacement = self._repair_read_message(outcome, candidate)
            if replacement is None:
                replacement = AssistantMessage.text(outcome.disclosure, cost=candidate.cost, usage=candidate.usage, raw_data=raw_data, generation_time_seconds=candidate.generation_time_seconds)
        elif outcome.decision == BLOCK:
            replacement = AssistantMessage.text(outcome.disclosure or f'The proposed state-changing action is not executable: {outcome.reason}.', cost=candidate.cost, usage=candidate.usage, raw_data=raw_data, generation_time_seconds=candidate.generation_time_seconds)
            self._clear_pending_repair()
        else:
            raise RuntimeError(f'unexpected pending repair outcome: {outcome.decision}')
        if isinstance(message, MultiToolMessage):
            state.messages.extend(message.tool_messages)
        else:
            state.messages.append(message)
        state.messages.append(replacement)
        return (replacement, state)

    def generate_next_message(self, message, state: LLMAgentState):
        if isinstance(message, UserMessage) and (not message.is_tool_call()):
            self.adapter.receive_context_answer(message.content, self._latest_visible_text(state))
        self._observe_tool(message, state)
        self.adapter.update_witness_state(state_cache=self.state_cache, witness_fields=self.global_witness_fields, evidence_ids=tuple(self.witness_evidence))
        confirmation = self._try_confirmation(message, state)
        if confirmation is not None:
            return confirmation
        if isinstance(message, UserMessage) and (not message.is_tool_call()):
            self.user_text_history.append(message.content)
        repair_replay = self._try_pending_repair_replay(message, state)
        if repair_replay is not None:
            return repair_replay
        candidate = normalize_half_duplex_assistant_message(self._generate_next_message(message, state))
        calls = candidate.tool_calls or []
        mutating = [call for call in calls if call.name in self.mutating_tool_names]
        if not mutating:
            state.messages.append(candidate)
            return (candidate, state)
        native_calls = tuple((self._native_candidate(call, index) for index, call in enumerate(mutating)))
        outcome = self.adapter.handle_candidate(NativeCandidateEnvelope(_message_bytes(candidate), native_calls))
        if outcome.decision == ASK_CONFIRMATION:
            self._clear_pending_repair()
            self.pending_candidate = candidate
            self.pending_calls = {str(call.id): call for call in mutating}
            replacement = AssistantMessage.text(outcome.disclosure, cost=candidate.cost, usage=candidate.usage, raw_data={'provider_response': candidate.raw_data, 'acg': list(outcome.audit_events)}, generation_time_seconds=candidate.generation_time_seconds)
        elif outcome.decision == REPAIR_WITNESS:
            self.pending_repair_candidate = candidate
            self.pending_repair_calls = {str(call.id): call for call in mutating}
            replacement = self._repair_read_message(outcome, candidate)
            if replacement is None:
                replacement = AssistantMessage.text(outcome.disclosure, cost=candidate.cost, usage=candidate.usage, raw_data={'provider_response': candidate.raw_data, 'acg': list(outcome.audit_events)}, generation_time_seconds=candidate.generation_time_seconds)
        elif outcome.decision == BLOCK:
            replacement = AssistantMessage.text(outcome.disclosure or f'The proposed state-changing action is not executable: {outcome.reason}.', cost=candidate.cost, usage=candidate.usage, raw_data={'provider_response': candidate.raw_data, 'acg': list(outcome.audit_events)}, generation_time_seconds=candidate.generation_time_seconds)
            if outcome.reason != 'duplicate_repair_frontier_suppressed':
                self._clear_pending_repair()
        elif outcome.decision == REPLAY:
            selected = next((call for call in mutating if str(call.id) == outcome.selected_candidate_id))
            if outcome.outbound_bytes != _call_bytes(selected):
                raise RuntimeError('persistent grant replay bytes changed')
            replacement = candidate.model_copy(update={'tool_calls': [selected], 'content': None, 'raw_data': {'provider_response': candidate.raw_data, 'acg': list(outcome.audit_events)}})
            self.executed_by_call_id[selected.id] = (str(self.tool_manifest.manifest['tools'][selected.name]['effect_schema']), str(selected.arguments.get('reservation_id', '')))
        elif outcome.decision == PASSTHROUGH:
            replacement = candidate
        else:
            raise RuntimeError(f'unexpected adapter outcome: {outcome.decision}')
        state.messages.append(replacement)
        return (replacement, state)

def create_tau_airline_agent(tools, domain_policy, **kwargs):
    db_path = os.environ.get('ACG_AIRLINE_DB_PATH')
    if not db_path:
        raise RuntimeError('ACG_AIRLINE_DB_PATH is required')
    return TauAirlineACGAgent(tools=tools, domain_policy=domain_policy, llm=kwargs.get('llm'), llm_args=kwargs.get('llm_args'), db_path=Path(db_path))
__all__ = ['TauAirlineACGAgent', 'create_tau_airline_agent', 'normalize_half_duplex_assistant_message']
