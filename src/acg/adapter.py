from __future__ import annotations
import copy
import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping
from .core import ASK, AUTHORIZE, BLOCK, AuthorizationClosureEngine, expression_atoms
from .manifest import CandidateCompilation, ManifestCompiler
from .mediator import TrustedMediator, canonical
from .session import AuthorizationSession, SessionContext
from .repair import context_answer, questions, rejection_details, render_rejection, render_repair, semantic_repair
from .serialization import UNKNOWN, SerializationCandidate, actionable_witness_repair, choose_serialization_candidate, probe_policy
PASSTHROUGH = 'passthrough'
ASK_CONFIRMATION = 'ask_confirmation'
REPAIR_WITNESS = 'repair_witness'
REPLAY = 'replay'

@dataclass(frozen=True)
class NativeCallCandidate:
    candidate_id: str
    tool_name: str
    arguments: dict[str, Any]
    runtime_mutation_signal: bool
    replay_bytes: bytes
    context_commitments: dict[str, Any] = field(default_factory=dict)
    projected_witness_fields: dict[str, Any] = field(default_factory=dict)
    group_id: str | None = None
    child_id: str | None = None

@dataclass(frozen=True)
class NativeCandidateEnvelope:
    wire_bytes: bytes
    calls: tuple[NativeCallCandidate, ...]

@dataclass(frozen=True)
class AdapterOutcome:
    decision: str
    reason: str
    outbound_bytes: bytes | None = None
    disclosure: str | None = None
    proposal_id: str | None = None
    selected_candidate_id: str | None = None
    repair: dict[str, Any] | None = None
    audit_events: tuple[dict[str, Any], ...] = ()

@dataclass
class _PreparedCall:
    native: NativeCallCandidate
    compilation: CandidateCompilation
    serialization: SerializationCandidate

@dataclass
class _PendingAuthorization:
    native: NativeCallCandidate
    engine: AuthorizationClosureEngine
    proposal_id: str
    disclosure: str
    canonical_call: str
    context: SessionContext
    fingerprint: str
    renew: bool

@dataclass
class _PendingRepair:
    envelope: NativeCandidateEnvelope
    immutable_candidate_sha256: str
    observation_version: str
    action_sha256: str
    repair_sha256: str
    repair: dict[str, Any]
    disclosure: str
EffectSpecLoader = Callable[[Mapping[str, Any], CandidateCompilation], Mapping[str, Any]]

def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _canonical_call(call: NativeCallCandidate) -> str:
    return canonical({'arguments': copy.deepcopy(call.arguments), 'tool': call.tool_name})

class AuthorizationAdapter:

    def __init__(self, *, tool_manifest: Mapping[str, Any], recovery_manifest: Mapping[str, Any], effect_spec_loader: EffectSpecLoader, state_cache: Mapping[str, Any] | None=None, witness_fields: Mapping[str, Any] | None=None, witness_evidence: tuple[str, ...]=(), witness_projector: Callable[[SerializationCandidate], Mapping[str, Any]] | None=None):
        self.witness_projector = witness_projector
        self.compiler = ManifestCompiler(tool_manifest)
        self.recovery_manifest = copy.deepcopy(dict(recovery_manifest))
        self._validate_recovery_manifest()
        self.effect_spec_loader = effect_spec_loader
        self.state_cache = copy.deepcopy(dict(state_cache or {}))
        self.witness_fields = copy.deepcopy(dict(witness_fields or {}))
        self.witness_evidence = tuple((str(value) for value in witness_evidence))
        self.mediator = TrustedMediator()
        self.session = AuthorizationSession()
        self._pending_control: SessionContext | None = None
        self.pending: _PendingAuthorization | None = None
        self.pending_repair: _PendingRepair | None = None
        self._emitted_repair_frontiers: set[str] = set()
        self._context_proposals: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _repair_is_actionable(repair: Mapping[str, Any]) -> bool:
        nested = repair.get('candidates') or []
        if nested:
            return any((isinstance(row, Mapping) and isinstance(row.get('repair'), Mapping) and AuthorizationAdapter._repair_is_actionable(row['repair']) for row in nested))
        if repair.get('required_witness_atoms'):
            return True
        if repair.get('context_questions'):
            return True
        return any(repair.get('native_witness_tools', {}).values())

    @staticmethod
    def _immutable_envelope_payload(envelope: NativeCandidateEnvelope) -> dict[str, Any]:
        return {'wire_bytes_sha256': _sha256(envelope.wire_bytes), 'calls': [{'candidate_id': call.candidate_id, 'tool_name': call.tool_name, 'arguments': copy.deepcopy(call.arguments), 'runtime_mutation_signal': call.runtime_mutation_signal, 'replay_bytes_sha256': _sha256(call.replay_bytes), **({'group_id': call.group_id, 'child_id': call.child_id} if call.group_id is not None or call.child_id is not None else {})} for call in envelope.calls]}

    @classmethod
    def _immutable_envelope_sha256(cls, envelope: NativeCandidateEnvelope) -> str:
        return _sha256(canonical(cls._immutable_envelope_payload(envelope)).encode('utf-8'))

    def _repair_observation_version(self, envelope: NativeCandidateEnvelope) -> str:
        payload = {'state_cache': self.state_cache, 'witness_fields': self.witness_fields, 'witness_evidence': list(self.witness_evidence), 'candidate_observations': [{'context_commitments': self.proposed_context_for(call), 'projected_witness_fields': copy.deepcopy(call.projected_witness_fields)} for call in envelope.calls]}
        return _sha256(canonical(payload).encode('utf-8'))

    @staticmethod
    def _action_sha256(envelope: NativeCandidateEnvelope) -> str:
        payload = [{'tool_name': call.tool_name, 'arguments': copy.deepcopy(call.arguments), 'runtime_mutation_signal': call.runtime_mutation_signal, **({'group_id': call.group_id, 'child_id': call.child_id} if call.group_id is not None or call.child_id is not None else {})} for call in envelope.calls]
        return _sha256(canonical(payload).encode('utf-8'))

    def pending_repair_observation_changed(self, envelope: NativeCandidateEnvelope) -> bool:
        pending = self.pending_repair
        if pending is None:
            return False
        immutable = self._immutable_envelope_sha256(envelope)
        if immutable != pending.immutable_candidate_sha256:
            raise RuntimeError('pending repair candidate bytes or arguments changed')
        return self._repair_observation_version(envelope) != pending.observation_version

    def cancel_pending_repair(self) -> None:
        self.pending_repair = None

    def proposed_context_for(self, call: NativeCallCandidate) -> dict[str, Any]:
        return copy.deepcopy({**self._context_proposals.get(_canonical_call(call), {}), **call.context_commitments})

    def context_proposals(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        key = canonical({'tool': tool_name, 'arguments': dict(arguments)})
        return copy.deepcopy(self._context_proposals.get(key, {}))

    def receive_context_answer(self, text: str, latest_visible_disclosure: str) -> bool:
        pending = self.pending_repair
        if pending is None or latest_visible_disclosure != pending.disclosure:
            return False
        fields = context_answer(text, pending.repair, self.recovery_manifest.get('context_repair_prompts', {}))
        if not fields:
            return False
        nested = pending.repair.get('candidates')
        allowed = {row['candidate_id']: {q['atom'] for q in questions(row['repair'])} for row in nested} if nested else {call.candidate_id: {q['atom'] for q in questions(pending.repair)} for call in pending.envelope.calls if call.runtime_mutation_signal}
        for call in pending.envelope.calls:
            scoped = {k: v for k, v in fields.items() if k in allowed.get(call.candidate_id, set())}
            if scoped:
                self._context_proposals.setdefault(_canonical_call(call), {}).update(copy.deepcopy(scoped))
        return True

    def _validate_recovery_manifest(self) -> None:
        profiles = self.recovery_manifest.get('tools')
        repairs = self.recovery_manifest.get('policy_repairs', {})
        if not isinstance(profiles, Mapping):
            raise ValueError('recovery manifest tools must be an object')
        if not isinstance(repairs, Mapping):
            raise ValueError('recovery manifest policy_repairs must be an object')
        manifested_tools = self.compiler.manifest['tools']
        for identifier, profile in profiles.items():
            if identifier not in manifested_tools:
                raise ValueError('recovery profile references an unmanifested tool')
            if not isinstance(profile, Mapping):
                raise ValueError('recovery tool profiles must be objects')
            if manifested_tools[identifier].get('kind') != 'effect':
                raise ValueError('recovery profiles may describe only effects')
            if profile.get('effect_schema') != manifested_tools[identifier].get('effect_schema'):
                raise ValueError('recovery and tool manifests disagree on effect schema')
            transition = profile.get('predicted_transition')
            if transition is not None and (not isinstance(transition, Mapping)):
                raise ValueError('predicted_transition must be an object or null')

    def update_witness_state(self, *, state_cache: Mapping[str, Any] | None=None, witness_fields: Mapping[str, Any] | None=None, evidence_ids: tuple[str, ...]=()) -> None:
        changed = state_cache is not None and canonical(state_cache) != canonical(self.state_cache) or (witness_fields is not None and canonical(witness_fields) != canonical(self.witness_fields))
        if changed and self.witness_projector is None:
            self.session.invalidate_projections()
        if state_cache is not None and canonical(state_cache) != canonical(self.state_cache):
            self.state_cache = copy.deepcopy(dict(state_cache))
        if witness_fields is not None and canonical(witness_fields) != canonical(self.witness_fields):
            self.witness_fields = copy.deepcopy(dict(witness_fields))
        if evidence_ids:
            self.witness_evidence = tuple((str(value) for value in evidence_ids))
        for context in self.session.contexts.values():
            if self.witness_projector is not None:
                context.candidate = replace(context.candidate, projected_witness_fields=copy.deepcopy(dict(self.witness_projector(context.candidate))))
            self.session.observe(context, self.state_cache, self.witness_fields)

    def _profile(self, identifier: str) -> Mapping[str, Any]:
        value = self.recovery_manifest['tools'].get(identifier)
        if not isinstance(value, Mapping):
            raise KeyError('manifested effect has no recovery profile')
        return value

    def _prepare_calls(self, envelope: NativeCandidateEnvelope) -> tuple[list[_PreparedCall], list[tuple[NativeCallCandidate, CandidateCompilation]]]:
        prepared: list[_PreparedCall] = []
        compiled: list[tuple[NativeCallCandidate, CandidateCompilation]] = []
        seen_ids: set[str] = set()
        for index, supplied in enumerate(envelope.calls):
            if supplied.candidate_id in seen_ids:
                raise ValueError('candidate identifiers must be unique')
            seen_ids.add(supplied.candidate_id)
            native = NativeCallCandidate(candidate_id=str(supplied.candidate_id), tool_name=str(supplied.tool_name), arguments=copy.deepcopy(dict(supplied.arguments)), runtime_mutation_signal=bool(supplied.runtime_mutation_signal), replay_bytes=bytes(supplied.replay_bytes), context_commitments=copy.deepcopy(self.proposed_context_for(supplied)), projected_witness_fields=copy.deepcopy(dict(supplied.projected_witness_fields)), group_id=supplied.group_id, child_id=supplied.child_id)
            compilation = self.compiler.compile_candidate(tool_name=native.tool_name, arguments=native.arguments, runtime_mutation_signal=native.runtime_mutation_signal)
            if compilation.decision != 'effect':
                compiled.append((native, compilation))
                continue
            if compilation.request is None:
                raise RuntimeError('effect compilation omitted its request')
            try:
                profile = self._profile(native.tool_name)
            except KeyError:
                compiled.append((native, compilation))
                continue
            spec = copy.deepcopy(dict(self.effect_spec_loader(profile, compilation)))
            metadata = spec.get('execution_metadata', {})
            allowed_context = {str(value) for value in metadata.get('context_commitments', [])}
            unexpected_context = set(native.context_commitments) - allowed_context
            if unexpected_context:
                compiled.append((native, CandidateCompilation('block', 'undeclared_context_commitment')))
                continue
            candidate = SerializationCandidate(candidate_id=native.candidate_id, request=replace(compilation.request, group_id=native.group_id, child_id=native.child_id), effect_spec=spec, predicted_transition=copy.deepcopy(profile.get('predicted_transition')), original_index=index, context_commitments=copy.deepcopy(native.context_commitments), projected_witness_fields=copy.deepcopy(native.projected_witness_fields))
            prepared.append(_PreparedCall(native, compilation, candidate))
            compiled.append((native, compilation))
        return (prepared, compiled)

    def _repair_for(self, prepared: _PreparedCall, proof: Mapping[str, Any]) -> dict[str, Any]:
        spec_with_repairs = copy.deepcopy(prepared.serialization.effect_spec)
        spec_with_repairs['policy_repairs'] = copy.deepcopy(self.recovery_manifest.get('policy_repairs', {}))
        repair = actionable_witness_repair(policy_decision_proof=proof, effect_spec=spec_with_repairs, tool_manifest=self.compiler.manifest)
        allowed = {str(identifier) for identifier, entry in self.compiler.manifest['tools'].items() if isinstance(entry, Mapping) and entry.get('kind') == 'witness'}
        for names in repair['native_witness_tools'].values():
            if any((name not in allowed for name in names)):
                raise RuntimeError('witness repair emitted an unmanifested producer')
        declared_context = {str(value) for value in prepared.serialization.effect_spec.get('execution_metadata', {}).get('context_commitments', [])}
        repair['required_context_commitments'] = sorted(set(repair['required_witness_atoms']) & declared_context)
        prompts = self.recovery_manifest.get('context_repair_prompts', {})
        questions = []
        for atom in repair['required_context_commitments']:
            prompt = prompts.get(atom) if isinstance(prompts, Mapping) else None
            if isinstance(prompt, Mapping) and isinstance(prompt.get('question'), str):
                questions.append({'atom': atom, 'question': str(prompt['question']), 'options': [str(value) for value in prompt.get('options', [])]})
        repair['context_questions'] = questions
        return repair

    @staticmethod
    def _short_repair(repair: Mapping[str, Any]) -> str:
        return render_repair(repair)

    def _unknown_repairs(self, prepared: list[_PreparedCall]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for value in prepared:
            probe = probe_policy(value.serialization, state_cache=self.state_cache, witness_fields=self.witness_fields)
            if probe.state != UNKNOWN:
                continue
            rows.append({'candidate_id': value.native.candidate_id, 'action': {'tool': value.native.tool_name, 'arguments': copy.deepcopy(value.native.arguments)}, 'repair': self._repair_for(value, probe.decision_proof)})
        return rows

    def _handle_candidate(self, envelope: NativeCandidateEnvelope) -> AdapterOutcome:
        if self.pending is not None or self._pending_control is not None:
            return self._audit_block('confirmation_already_pending')
        prepared, compiled = self._prepare_calls(envelope)
        prepared_ids = {row.native.candidate_id for row in prepared}
        failures = [(call, result) for call, result in compiled if result.decision == 'block' or (result.decision == 'effect' and call.candidate_id not in prepared_ids)]
        if failures:
            call, result = failures[0]
            reason = result.reason if result.decision == 'block' else 'recovery_profile_missing'
            if reason == 'candidate_argument_contract_failed':
                invalid_paths = sorted((str(value) for value in (result.details or {}).get('invalid_paths', [])))
                audit = {'decision': BLOCK, 'reason': reason, 'selected_candidate_id': call.candidate_id, 'invalid_paths': invalid_paths, 'free_text_can_satisfy': False, 'p0_invariant': 'native_argument_contract_before_authorization'}
                rendered = ', '.join(invalid_paths)
                return AdapterOutcome(BLOCK, reason, disclosure=f'THE PROPOSED ACTION HAS INVALID TYPED ARGUMENTS. Regenerate the native tool call with concrete values at: {rendered}. Do not place explanations or reason text in typed identifier fields.', selected_candidate_id=call.candidate_id, audit_events=(audit,))
            return self._audit_block(reason, selected_candidate_id=call.candidate_id)
        if not prepared:
            return AdapterOutcome(PASSTHROUGH, 'no_mutating_effect', outbound_bytes=bytes(envelope.wire_bytes))
        selected: _PreparedCall
        serialization_audit: dict[str, Any] | None = None
        if len(prepared) > 1:
            choice = choose_serialization_candidate([value.serialization for value in prepared], state_cache=self.state_cache, witness_fields=self.witness_fields)
            serialization_audit = {'decision': choice.decision, 'reason': choice.reason, 'policy_states': copy.deepcopy(choice.policy_states), 'remaining_feasible_after': copy.deepcopy(choice.remaining_feasible_after)}
            if choice.decision != 'select' or choice.selected_candidate_id is None:
                unknown = self._unknown_repairs(prepared)
                if unknown:
                    repair = {'candidates': unknown, 'free_text_can_satisfy': False}
                    audit = {'decision': ASK, 'reason': 'native_witness_repair_required', 'repair': copy.deepcopy(repair), 'serialization': serialization_audit}
                    return AdapterOutcome(REPAIR_WITNESS, 'native_witness_repair_required', repair=repair, audit_events=(audit,))
                audit = {'decision': BLOCK, 'reason': choice.reason, 'serialization': serialization_audit}
                return AdapterOutcome(BLOCK, choice.reason, audit_events=(audit,))
            selected = next((value for value in prepared if value.native.candidate_id == choice.selected_candidate_id))
        else:
            selected = prepared[0]
        context = self.session.install(selected.serialization)
        self.session.observe(context, self.state_cache, self.witness_fields)
        staged, changes = self.session.stage(context)
        decision = staged.prepare(context.request())
        if decision.reason == 'policy_unknown':
            repair = self._repair_for(selected, decision.proof)
            audit = {'decision': ASK, 'reason': 'native_witness_repair_required', 'selected_candidate_id': selected.native.candidate_id, 'repair': copy.deepcopy(repair)}
            return AdapterOutcome(REPAIR_WITNESS, 'native_witness_repair_required', selected_candidate_id=selected.native.candidate_id, repair=repair, audit_events=(audit,))
        if decision.reason == 'policy_refuted':
            details = rejection_details(staged, context.request(), {v: k for k, v in context.atoms.items()}, decision.proof)
            explanations = self.recovery_manifest.get('policy_failure_guidance', {})
            guidance = [explanations[name] for name in details['failed_conditions'] if isinstance(explanations.get(name), str) and explanations[name].strip()]
            if guidance:
                details['repair_guidance'] = guidance
            outcome = self._audit_block(decision.reason, selected_candidate_id=selected.native.candidate_id, proof=decision.proof)
            return replace(outcome, disclosure=render_rejection(details), audit_events=tuple(({**row, 'rejection_details': details} for row in outcome.audit_events)))
        is_group = context.request().group_id is not None or context.request().child_id is not None
        if is_group and decision.reason == 'group_child_binding_incomplete':
            repair = {'group_id': context.request().group_id, 'child_id': context.request().child_id, 'missing_child_fields': list(decision.repair_atoms), 'required_native_event': 'group_child_revision'}
            return AdapterOutcome(ASK, decision.reason, repair=repair, disclosure='The group child mapping is incomplete. Complete these fields through a native group-child revision and confirmation: ' + ', '.join(decision.repair_atoms), audit_events=({'decision': ASK, 'reason': decision.reason, 'repair': repair},))
        if is_group and decision.decision != AUTHORIZE and (decision.reason != 'group_consequence_closure_required'):
            return self._audit_block(decision.reason, proof=decision.proof)
        if is_group and decision.decision == AUTHORIZE:
            if decision.reservation_id is None:
                return self._audit_block(decision.reason, proof=decision.proof)
            staged.abort(decision.reservation_id)
            argument_atoms = {context.atoms[a] for a in context.candidate.request.arguments}
            if set(changes) - argument_atoms:
                return self._audit_block('group_context_requires_native_authorization')
            transaction = copy.deepcopy(self.session.engine)
            previous_event_count = len(transaction.event_log)
            group = transaction.groups[context.request().group_id]
            if changes:
                self.session._ingest({'event_type': 'commitment', 'fields': changes, 'evidence_ids': list(group.evidence_ids)}, engine=transaction)
            live = transaction.prepare(context.request())
            if live.decision != AUTHORIZE:
                return self._audit_block(live.reason, proof=live.proof)
            committed = transaction.commit(live.reservation_id)
            if committed.decision != AUTHORIZE:
                return self._audit_block(committed.reason, proof=committed.proof)
            self.session.publish(transaction, previous_event_count)
            self.session.mark_dispatched(context)
            return AdapterOutcome(REPLAY, 'persistent_group_child_committed', outbound_bytes=bytes(selected.native.replay_bytes), selected_candidate_id=selected.native.candidate_id, audit_events=({'decision': AUTHORIZE, 'reason': 'persistent_group_child_committed', 'proof': committed.proof, 'session': self.session.snapshot()},))
        if decision.decision == AUTHORIZE and (not changes):
            staged.abort(decision.reservation_id)
            prepared_live = self.session.engine.prepare(context.request())
            if prepared_live.decision == AUTHORIZE:
                committed_live = self.session.engine.commit(prepared_live.reservation_id)
                if committed_live.decision == AUTHORIZE:
                    self.session.mark_dispatched(context)
                    return AdapterOutcome(REPLAY, 'persistent_authorization_reused', outbound_bytes=bytes(selected.native.replay_bytes), selected_candidate_id=selected.native.candidate_id, audit_events=({'decision': AUTHORIZE, 'reason': 'persistent_authorization_reused', 'proof': committed_live.proof, 'session': self.session.snapshot()},))
            return self._audit_block('persistent_authorization_revalidation_failed')
        if decision.decision == AUTHORIZE:
            staged.abort(decision.reservation_id)
        if decision.decision == BLOCK and decision.reason != 'authorization_budget_exhausted':
            return self._audit_block(decision.reason, selected_candidate_id=selected.native.candidate_id, proof=decision.proof)
        renew = not is_group
        reverse_atoms = {v: k for k, v in context.atoms.items()}
        derived_atoms = [reverse_atoms[atom] for atom in decision.repair_atoms if atom in staged.bindings and atom in reverse_atoms and (staged.bindings[atom].kind == 'derived')]
        canonical_call = _canonical_call(selected.native)
        metadata = selected.serialization.effect_spec.get('execution_metadata', {})
        details = {}
        requested_details = metadata.get('disclosure_atoms', [])
        if requested_details:
            schema = selected.serialization.effect_spec['effects'][selected.serialization.request.schema_id]
            roots = set(schema.get('proof_atoms', []))
            for policy in schema.get('policies', []):
                roots.update(expression_atoms(policy.get('expression', policy)))
            todo = [context.atoms[name] for name in roots if name in context.atoms]
            covered = set()
            while todo:
                name = todo.pop()
                if name in covered:
                    continue
                covered.add(name)
                binding = staged.bindings.get(name)
                if binding is not None and binding.active:
                    todo.extend(binding.parents)
            for atom in requested_details:
                name = context.atoms.get(atom)
                binding = staged.bindings.get(name)
                if name not in covered or binding is None or (not binding.active):
                    raise ValueError('disclosed detail must be in the active candidate proof closure')
                if atom not in derived_atoms:
                    details[atom] = copy.deepcopy(binding.value)
        notices = metadata.get('confirmation_notices', [])
        if not isinstance(notices, list) or not all((isinstance(s, str) and s for s in notices)):
            raise ValueError('confirmation notices must be a list of nonempty strings')
        proposal = self.mediator.issue('closure_grant', {'derived_atoms': derived_atoms, 'derived_values': {atom: copy.deepcopy(staged.bindings[context.atoms[atom]].value) for atom in derived_atoms}, 'effect_schema': selected.serialization.request.schema_id, 'fields': copy.deepcopy({**selected.serialization.context_commitments, **selected.serialization.request.arguments}), 'context_commitments': copy.deepcopy(selected.serialization.context_commitments), 'executable_arguments': copy.deepcopy(selected.serialization.request.arguments), 'selected_call_canonical': canonical_call, 'selected_call_sha256': _sha256(canonical_call.encode('utf-8')), 'selected_tool_name': selected.native.tool_name, 'execution_budget': {'new_grant': renew, 'uses': 1}, **({'verified_details': details} if details else {}), **({'confirmation_notices': list(notices)} if notices else {}), **({'group_reference': {'group_id': context.request().group_id, 'child_id': context.request().child_id}} if is_group else {})})
        self.pending = _PendingAuthorization(native=copy.deepcopy(selected.native), engine=self.session.engine, proposal_id=proposal.proposal_id, disclosure=proposal.disclosure, canonical_call=canonical_call, context=context, fingerprint=self.session.fingerprint(context, staged), renew=renew)
        audit = {'decision': ASK, 'reason': 'canonical_native_confirmation_required', 'selected_candidate_id': selected.native.candidate_id, 'selected_call_sha256': _sha256(canonical_call.encode('utf-8')), 'proposal_id': proposal.proposal_id, 'session': self.session.snapshot(), 'repair_atoms': [reverse_atoms.get(a, 'execution_grant') for a in decision.repair_atoms], 'source_changes': [reverse_atoms[a] for a in changes]}
        if serialization_audit is not None:
            audit['serialization'] = serialization_audit
        return AdapterOutcome(ASK_CONFIRMATION, 'canonical_native_confirmation_required', disclosure=proposal.disclosure, proposal_id=proposal.proposal_id, selected_candidate_id=selected.native.candidate_id, audit_events=(audit,))

    def handle_candidate(self, envelope: NativeCandidateEnvelope) -> AdapterOutcome:
        outcome = self._handle_candidate(envelope)
        if outcome.decision != REPAIR_WITNESS or not outcome.repair:
            if outcome.decision == ASK_CONFIRMATION:
                self.pending_repair = None
            return outcome
        if not self._repair_is_actionable(outcome.repair):
            audit = {'decision': BLOCK, 'reason': 'non_actionable_repair_frontier', 'repair': copy.deepcopy(outcome.repair), 'free_text_can_satisfy': False, 'p0_invariant': 'no_empty_visible_repair'}
            return AdapterOutcome(BLOCK, 'non_actionable_repair_frontier', disclosure='THE PROPOSED ACTION CANNOT ENTER AUTHORIZATION: its UNKNOWN frontier has no typed witness, manifested producer, or context question. Regenerate a schema-valid native call or choose a different action; repeating free text cannot create authority.', selected_candidate_id=outcome.selected_candidate_id, audit_events=(audit,))
        action_sha = self._action_sha256(envelope)
        repair_sha = _sha256(canonical(semantic_repair(outcome.repair)).encode('utf-8'))
        observation = self._repair_observation_version(envelope)
        frontier_key = _sha256(canonical({'action_sha256': action_sha, 'repair_sha256': repair_sha, 'observation_version': observation}).encode('utf-8'))
        if frontier_key in self._emitted_repair_frontiers:
            audit = {'decision': BLOCK, 'reason': 'duplicate_repair_frontier_suppressed', 'action_sha256': action_sha, 'repair_sha256': repair_sha, 'observation_version': observation, 'visible_ask_emitted': False, 'p0_invariant': 'one_visible_repair_per_frontier_version'}
            disclosure = 'THE PREVIOUS EVIDENCE REQUEST IS STILL PENDING. Answer the displayed field=<choice> form, obtain the requested authoritative evidence, or choose a different action. An unchanged proposal will not create a new confirmation request.'
            if self.pending_repair is not None and self.pending_repair.action_sha256 == action_sha:
                self.pending_repair.disclosure = disclosure
            return AdapterOutcome(BLOCK, 'duplicate_repair_frontier_suppressed', disclosure=disclosure, selected_candidate_id=outcome.selected_candidate_id, audit_events=(audit,))
        self._emitted_repair_frontiers.add(frontier_key)
        self.pending_repair = _PendingRepair(envelope=copy.deepcopy(envelope), immutable_candidate_sha256=self._immutable_envelope_sha256(envelope), observation_version=observation, action_sha256=action_sha, repair_sha256=repair_sha, repair=copy.deepcopy(outcome.repair), disclosure=self._short_repair(outcome.repair))
        audits = []
        for row in outcome.audit_events:
            updated = copy.deepcopy(dict(row))
            updated['visible_repair_compacted'] = True
            updated['pending_candidate_frozen'] = True
            updated['immutable_candidate_sha256'] = self.pending_repair.immutable_candidate_sha256
            updated['repair_observation_version'] = observation
            audits.append(updated)
        return replace(outcome, disclosure=self._short_repair(outcome.repair), audit_events=tuple(audits))

    def retry_pending_repair(self, envelope: NativeCandidateEnvelope) -> AdapterOutcome:
        pending = self.pending_repair
        if pending is None:
            return self._audit_block('pending_repair_missing')
        immutable = self._immutable_envelope_sha256(envelope)
        if immutable != pending.immutable_candidate_sha256:
            return self._audit_block('pending_repair_candidate_changed')
        observation = self._repair_observation_version(envelope)
        if observation == pending.observation_version:
            return self._audit_block('pending_repair_evidence_unchanged')
        self.pending_repair = None
        outcome = self.handle_candidate(envelope)
        audits = []
        for row in outcome.audit_events:
            updated = copy.deepcopy(dict(row))
            updated['pending_repair_candidate_replayed'] = True
            updated['model_regeneration_skipped'] = True
            updated['immutable_candidate_sha256'] = immutable
            updated['previous_repair_observation_version'] = pending.observation_version
            updated['current_repair_observation_version'] = observation
            audits.append(updated)
        return replace(outcome, audit_events=tuple(audits))

    def handle_confirmation(self, *, proposal_id: str, user_text: str, latest_visible_disclosure: str) -> AdapterOutcome:
        pending = self.pending
        if pending is None:
            return self._audit_block('pending_proposal_missing')
        if user_text != 'CONFIRM':
            self._clear_pending()
            return self._audit_block('response_not_exact_native_confirm', selected_candidate_id=pending.native.candidate_id)
        self.session.observe(pending.context, self.state_cache, self.witness_fields)
        staged, _ = self.session.stage(pending.context)
        if self.session.fingerprint(pending.context, staged) != pending.fingerprint:
            self._clear_pending()
            return self._audit_block('authorization_snapshot_changed_after_disclosure')
        result = self.mediator.respond(proposal_id=proposal_id, user_text=user_text, latest_visible_disclosure=latest_visible_disclosure)
        if result.decision != AUTHORIZE:
            selected_id = pending.native.candidate_id
            self._clear_pending()
            return self._audit_block(result.reason, selected_candidate_id=selected_id)
        if _canonical_call(pending.native) != pending.canonical_call:
            self._clear_pending()
            return self._audit_block('selected_call_changed_after_disclosure', selected_candidate_id=pending.native.candidate_id)
        event_start = len(self.session.events)
        transaction = copy.deepcopy(pending.engine)
        previous_event_count = len(transaction.event_log)
        self.session.grant(pending.context, result.events, renew=pending.renew, engine=transaction)
        prepared = transaction.prepare(pending.context.request())
        if prepared.decision != AUTHORIZE or prepared.reservation_id is None:
            selected_id = pending.native.candidate_id
            proof = copy.deepcopy(prepared.proof)
            self._clear_pending()
            return self._audit_block('post_confirmation_closure_failed', selected_candidate_id=selected_id, proof=proof)
        committed = transaction.commit(prepared.reservation_id)
        if committed.decision != AUTHORIZE:
            selected_id = pending.native.candidate_id
            proof = copy.deepcopy(committed.proof)
            self._clear_pending()
            return self._audit_block(committed.reason, selected_candidate_id=selected_id, proof=proof)
        self.session.publish(transaction, previous_event_count)
        self.session.mark_dispatched(pending.context)
        replay_bytes = bytes(pending.native.replay_bytes)
        selected_id = pending.native.candidate_id
        audit = {'decision': AUTHORIZE, 'reason': 'confirmed_native_call_byte_replay', 'selected_candidate_id': selected_id, 'selected_call_sha256': _sha256(pending.canonical_call.encode('utf-8')), 'replay_bytes_sha256': _sha256(replay_bytes), 'model_regeneration_skipped': True, 'proof': copy.deepcopy(committed.proof), 'authorization_events': copy.deepcopy(self.session.events[event_start:]), 'session': self.session.snapshot()}
        self.pending = None
        return AdapterOutcome(REPLAY, 'confirmed_native_call_byte_replay', outbound_bytes=replay_bytes, selected_candidate_id=selected_id, audit_events=(audit,))

    def issue_control(self, context_key: str, event_type: str, payload: Mapping[str, Any]):
        if self.pending is not None or self._pending_control is not None:
            raise RuntimeError('authorization already pending')
        if event_type not in {'revision', 'revoke', 'group_grant', 'group_child_revision', 'group_child_revoke', 'group_shared_revision', 'group_member_add'}:
            raise ValueError('unsupported native control')
        context = self.session.contexts[context_key]
        data = copy.deepcopy(dict(payload))
        if event_type == 'revision':
            if not data.get('fields') or any((a not in context.atoms or not context.atoms[a].startswith('source:') for a in data['fields'])):
                raise ValueError('revision must target declared source commitments')
        if event_type == 'revoke':
            if not data.get('atoms') or any((a not in context.atoms for a in data['atoms'])):
                raise ValueError('revocation must target declared atoms')
        if event_type == 'group_grant':
            data['schema_id'] = context.schema
        elif event_type.startswith('group_'):
            group = self.session.engine.groups[data['group_id']]
            if self.session.engine.spec['effects'][group.schema_id]['group_family'] != self.session.engine.spec['effects'][context.schema]['group_family']:
                raise ValueError('group belongs to a different effect family')
        proposal = self.mediator.issue(event_type, data)
        self._pending_control = context
        return proposal

    def handle_control_confirmation(self, *, proposal_id: str, user_text: str, latest_visible_disclosure: str) -> AdapterOutcome:
        context = self._pending_control
        if context is None:
            return self._audit_block('pending_control_missing')
        if user_text != 'CONFIRM':
            self._clear_pending()
            return self._audit_block('response_not_exact_native_confirm')
        result = self.mediator.respond(proposal_id=proposal_id, user_text=user_text, latest_visible_disclosure=latest_visible_disclosure)
        self._pending_control = None
        if result.decision != AUTHORIZE:
            self._clear_pending()
            return self._audit_block(result.reason)
        start = len(self.session.events)
        staged = copy.deepcopy(self.session.engine)
        events = []
        try:
            for original in result.events:
                event = copy.deepcopy(original)
                if event['event_type'] == 'revision':
                    event['fields'] = {context.atoms[a]: v for a, v in event['fields'].items()}
                elif event['event_type'] == 'revoke':
                    event['atoms'] = [context.atoms[a] for a in event['atoms']]
                staged.ingest_event(event)
                events.append(event)
        except (KeyError, ValueError, TypeError):
            return self._audit_block('invalid_native_control_payload')
        for event in events:
            self.session._ingest(event)
        return AdapterOutcome(AUTHORIZE, 'native_control_committed', audit_events=({'decision': AUTHORIZE, 'reason': 'native_control_committed', 'authorization_events': copy.deepcopy(self.session.events[start:]), 'session': self.session.snapshot()},))

    def _clear_pending(self) -> None:
        if self.mediator.pending is not None:
            self.mediator.cancel(self.mediator.pending.proposal_id)
        self.pending = None
        self._pending_control = None

    @staticmethod
    def _audit_block(reason: str, *, selected_candidate_id: str | None=None, proof: Mapping[str, Any] | None=None) -> AdapterOutcome:
        audit: dict[str, Any] = {'decision': BLOCK, 'reason': reason}
        if selected_candidate_id is not None:
            audit['selected_candidate_id'] = selected_candidate_id
        if proof:
            audit['proof'] = copy.deepcopy(dict(proof))
        return AdapterOutcome(BLOCK, reason, selected_candidate_id=selected_candidate_id, audit_events=(audit,))
__all__ = ['AuthorizationAdapter', 'ASK_CONFIRMATION', 'AdapterOutcome', 'NativeCallCandidate', 'NativeCandidateEnvelope', 'PASSTHROUGH', 'REPAIR_WITNESS', 'REPLAY']
