from __future__ import annotations
import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def _pretty(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)

@dataclass(frozen=True)
class MediatedProposal:
    proposal_id: str
    proposal_type: str
    payload: dict[str, Any]
    payload_sha256: str
    disclosure: str
    disclosure_sha256: str

@dataclass(frozen=True)
class MediatorResult:
    decision: str
    reason: str
    events: tuple[dict[str, Any], ...] = ()

class TrustedMediator:

    def __init__(self):
        self.pending: MediatedProposal | None = None
        self._counter = 0

    @staticmethod
    def _render(proposal_id: str, proposal_type: str, payload: Mapping[str, Any]) -> str:
        if proposal_type == 'closure_grant':
            call = payload.get('selected_call_canonical')
            if isinstance(call, str):
                try:
                    call = json.loads(call)
                except json.JSONDecodeError:
                    pass
            context = payload.get('context_commitments') or {}
            consequences = payload.get('derived_values') or {}
            payload_hash = hashlib.sha256(canonical(dict(payload)).encode('utf-8')).hexdigest()
            sections = ['TRUSTED ACTION CONFIRMATION', f'Proposal ID: {proposal_id}', f'Exact action:\n{_pretty(call)}']
            if context:
                sections.append(f'Context commitments:\n{_pretty(context)}')
            if payload.get('verified_details'):
                sections.append('Action details from the checked proof:\n' + _pretty(payload['verified_details']))
            if consequences:
                sections.append(f'Material consequences:\n{_pretty(consequences)}')
            if payload.get('confirmation_notices'):
                sections.extend(('Before confirming: ' + notice for notice in payload['confirmation_notices']))
            if payload.get('execution_budget', {}).get('new_grant'):
                sections.append('Execution budget: one use. This confirmation grants one new execution; it does not replay an old approval.')
            if payload.get('group_reference'):
                sections.append('Existing group child: ' + canonical(payload['group_reference']))
                sections.append('This confirms the missing consequences only. The existing group child budget applies; no additional execution budget is granted.')
            sections.extend([f'Bound proposal SHA256: {payload_hash}', 'Reply exactly CONFIRM to authorize this unchanged action and any explicitly listed local constraint revision. Any other text is not authorization.'])
            return '\n'.join(sections)
        body = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, indent=2)
        return f'TRUSTED AUTHORIZATION PROPOSAL\nProposal ID: {proposal_id}\nType: {proposal_type}\nPayload:\n{body}\nReply exactly CONFIRM to authorize this proposal. Any other text is not authorization.'

    def issue(self, proposal_type: str, payload: Mapping[str, Any]) -> MediatedProposal:
        if self.pending is not None:
            raise RuntimeError('one trusted mediator may expose only one pending proposal')
        if proposal_type not in {'commitment', 'closure_grant', 'derived_repair', 'group_grant', 'group_child_revision', 'group_child_revoke', 'group_shared_revision', 'group_member_add', 'revision', 'revoke'}:
            raise ValueError(f'unsupported mediated proposal type: {proposal_type}')
        if not isinstance(payload, Mapping) or not payload:
            raise ValueError('mediated payload must be a non-empty object')
        self._counter += 1
        proposal_id = f'proposal-{self._counter}'
        frozen_payload = copy.deepcopy(dict(payload))
        payload_sha = hashlib.sha256(canonical(frozen_payload).encode('utf-8')).hexdigest()
        disclosure = self._render(proposal_id, proposal_type, frozen_payload)
        proposal = MediatedProposal(proposal_id=proposal_id, proposal_type=proposal_type, payload=frozen_payload, payload_sha256=payload_sha, disclosure=disclosure, disclosure_sha256=hashlib.sha256(disclosure.encode('utf-8')).hexdigest())
        self.pending = proposal
        return proposal

    @staticmethod
    def _events(proposal: MediatedProposal) -> tuple[dict[str, Any], ...]:
        evidence_id = f'trusted-mediator:{proposal.proposal_id}:{proposal.disclosure_sha256}'
        payload = proposal.payload
        if proposal.proposal_type in {'commitment', 'revision'}:
            return ({'event_type': proposal.proposal_type, 'fields': copy.deepcopy(payload['fields']), 'evidence_ids': [evidence_id]},)
        if proposal.proposal_type == 'closure_grant':
            events = [{'event_type': 'commitment', 'fields': copy.deepcopy(payload['fields']), 'evidence_ids': [evidence_id]}]
            events.extend(({'event_type': 'confirm_derived', 'atom_id': str(atom_id), 'evidence_id': evidence_id} for atom_id in payload.get('derived_atoms', [])))
            return tuple(events)
        if proposal.proposal_type == 'derived_repair':
            atom_ids = tuple((str(value) for value in payload['atom_ids']))
            return tuple(({'event_type': 'confirm_derived', 'atom_id': atom_id, 'evidence_id': evidence_id} for atom_id in atom_ids))
        event = copy.deepcopy(payload)
        event['event_type'] = proposal.proposal_type
        if proposal.proposal_type == 'group_grant':
            event['evidence_ids'] = [evidence_id]
        else:
            event['evidence_id'] = evidence_id
        return (event,)

    def respond(self, *, proposal_id: str, user_text: str, latest_visible_disclosure: str) -> MediatorResult:
        proposal = self.pending
        if proposal is None or proposal.proposal_id != proposal_id:
            return MediatorResult('reject', 'pending_proposal_missing_or_mismatched')
        if latest_visible_disclosure != proposal.disclosure:
            self.pending = None
            return MediatorResult('reject', 'visible_binding_mismatch')
        observed_hash = hashlib.sha256(latest_visible_disclosure.encode('utf-8')).hexdigest()
        if observed_hash != proposal.disclosure_sha256:
            self.pending = None
            return MediatorResult('reject', 'disclosure_hash_mismatch')
        if user_text.strip() != 'CONFIRM':
            return MediatorResult('no_authority', 'response_not_exact_confirm')
        self.pending = None
        return MediatorResult('authorize', 'exact_trusted_confirmation', self._events(proposal))

    def cancel(self, proposal_id: str) -> None:
        if self.pending is None or self.pending.proposal_id != proposal_id:
            raise ValueError('pending proposal missing or mismatched')
        self.pending = None
__all__ = ['MediatedProposal', 'MediatorResult', 'TrustedMediator']
