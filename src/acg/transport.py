from __future__ import annotations
import json
import os
import re
import time
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any
from litellm import ModelResponse
MODEL_ROUTES: dict[str, dict[str, Any]] = {}

def normalized_model(model: str) -> str:
    return model.split('/', 1)[-1]

def model_route(model: str) -> dict[str, Any]:
    return MODEL_ROUTES.get(normalized_model(model), {})

def _json_pointer(root: Any, reference: str) -> Any:
    if not reference.startswith('#/'):
        raise ValueError(f'only local JSON Schema references are supported: {reference}')
    value = root
    for raw_token in reference[2:].split('/'):
        token = raw_token.replace('~1', '/').replace('~0', '~')
        if not isinstance(value, dict) or token not in value:
            raise ValueError(f'unresolved local JSON Schema reference: {reference}')
        value = value[token]
    return value

def _inline_schema_node(node: Any, root: dict[str, Any], stack: tuple[str, ...]) -> Any:
    if isinstance(node, list):
        return [_inline_schema_node(item, root, stack) for item in node]
    if not isinstance(node, dict):
        return node
    if '$ref' in node:
        reference = node['$ref']
        if not isinstance(reference, str):
            raise ValueError('JSON Schema $ref must be a string')
        if reference in stack:
            raise ValueError(f'cyclic local JSON Schema reference: {reference}')
        target = deepcopy(_json_pointer(root, reference))
        siblings = {key: value for key, value in node.items() if key != '$ref'}
        if not isinstance(target, dict):
            raise ValueError(f'JSON Schema reference must resolve to an object: {reference}')
        target.update(siblings)
        return _inline_schema_node(target, root, stack + (reference,))
    return {key: _inline_schema_node(value, root, stack) for key, value in node.items() if key not in {'$defs', 'definitions'}}

def inline_local_schema_refs(schema: dict[str, Any]) -> dict[str, Any]:
    root = deepcopy(schema)
    return _inline_schema_node(root, root, ())

def compatible_tools(tools: list[dict], mode: str | None) -> list[dict]:
    if mode is None:
        return tools
    if mode != 'inline_local_refs':
        raise ValueError(f'unsupported tool schema compatibility mode: {mode}')
    result = deepcopy(tools)
    for tool in result:
        function = tool.get('function')
        if not isinstance(function, dict):
            continue
        parameters = function.get('parameters')
        if isinstance(parameters, dict):
            function['parameters'] = inline_local_schema_refs(parameters)
    return result

def resolve_base_url(model: str, kwargs: dict[str, Any]) -> str:
    route = model_route(model)
    return str(kwargs.get('api_base') or kwargs.get('base_url') or route.get('base_url') or os.environ['MODEL_BASE_URL']).rstrip('/')

def make_payload(model: str, messages: list[dict], tools: list[dict] | None, tool_choice, kwargs: dict[str, Any]) -> dict[str, Any]:
    params = dict(kwargs)
    for key in ('api_base', 'base_url', 'api_key', 'timeout', 'num_retries'):
        params.pop(key, None)
    if params.pop('stream', False):
        raise ValueError('direct transport is non-streaming')
    extra_body = params.pop('extra_body', {}) or {}
    allowed = {'temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'seed', 'stop', 'response_format', 'parallel_tool_calls'}
    unknown = set(params) - allowed
    if unknown:
        raise ValueError(f'unsupported direct-transport parameters: {sorted(unknown)}')
    route = model_route(model)
    wire_model = route.get('wire_model') or normalized_model(model)
    payload = {'model': wire_model, 'messages': messages, **params, **extra_body}
    if tools:
        payload['tools'] = compatible_tools(tools, route.get('tool_schema_mode'))
    if tool_choice is not None:
        payload['tool_choice'] = tool_choice
    return payload

def _sanitized_error(error: urllib.error.HTTPError, secret: str | None=None) -> dict[str, Any]:
    try:
        raw = json.loads(error.read().decode('utf-8', errors='replace'))
        value = raw.get('error', raw) if isinstance(raw, dict) else {}
        if not isinstance(value, dict):
            value = {}
        safe = {key: value.get(key) for key in ('type', 'code', 'message') if value.get(key) is not None}
        encoded = json.dumps(safe, ensure_ascii=False)
        if secret:
            encoded = encoded.replace(secret, '[REDACTED]')
        encoded = re.sub('(?i)sk-[a-z0-9_-]{8,}', '[REDACTED]', encoded)
        return json.loads(encoded)
    except Exception:
        return {'type': 'unparseable_provider_error'}

def direct_completion(*, model: str, messages: list[dict], tools: list[dict] | None=None, tool_choice=None, **kwargs: Any) -> ModelResponse:
    timeout = float(kwargs.get('timeout', 180))
    retries = int(kwargs.get('num_retries', 2))
    route = model_route(model)
    key_env = route.get('key_env', 'OPENAI_API_KEY')
    key = os.environ.get(key_env)
    if not key:
        raise RuntimeError(f'{key_env} is required in process memory')
    payload = make_payload(model, messages, tools, tool_choice, kwargs)
    request = urllib.request.Request(resolve_base_url(model, kwargs) + '/chat/completions', data=json.dumps(payload, ensure_ascii=False).encode('utf-8'), headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json', 'Accept': 'application/json', 'Connection': 'close'}, method='POST')
    last_error: Exception | None = None
    last_detail: dict[str, Any] = {}
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = json.loads(response.read().decode('utf-8'))
            expected_response = route.get('expected_response_model', payload['model'])
            if str(raw.get('model', '')).split('/')[-1] != expected_response:
                raise RuntimeError('direct transport exact returned model mismatch')
            choices = raw.get('choices') or []
            if not choices:
                raise RuntimeError('Provider returned no choices')
            message = choices[0].get('message') or {}
            if not message.get('content') and not message.get('tool_calls'):
                refusal = message.get('refusal')
                if isinstance(refusal, str) and refusal.strip():
                    raw = deepcopy(raw)
                    raw['choices'][0]['message']['content'] = refusal
                else:
                    raise RuntimeError('Provider returned an empty message')
            return ModelResponse(**raw)
        except urllib.error.HTTPError as error:
            last_error = error
            last_detail = _sanitized_error(error, key)
            if attempt < retries:
                time.sleep(1)
        except Exception as error:
            last_error = error
            if attempt < retries:
                time.sleep(1)
    if isinstance(last_error, urllib.error.HTTPError):
        raise RuntimeError(f'direct transport HTTP {last_error.code}; provider_error={json.dumps(last_detail, sort_keys=True)}') from last_error
    raise RuntimeError(f'direct transport exhausted retries with {type(last_error).__name__}') from last_error
__all__ = ['MODEL_ROUTES', 'compatible_tools', 'direct_completion', 'inline_local_schema_refs', 'make_payload']
