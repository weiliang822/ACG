import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlparse


def model_settings(role, fallback=None):
    fallback = fallback or {}
    name = os.environ.get(f'{role}_MODEL', fallback.get('name'))
    base = os.environ.get(f'{role}_BASE_URL', os.environ.get('MODEL_BASE_URL', fallback.get('base', ''))).rstrip('/')
    key_env = f'{role}_API_KEY' if os.environ.get(f'{role}_API_KEY') else fallback.get('key_env', 'MODEL_API_KEY')
    if not name or not base or not os.environ.get(key_env):
        raise ValueError('Set the model name, endpoint, and credential environment variables described in README.md')
    url = urlparse(base)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Model endpoints must be HTTPS URLs without credentials, queries, or fragments')
    wire = name.removeprefix('openai/')
    shared = wire == fallback.get('wire')
    extra = json.loads(os.environ.get(f'{role}_EXTRA_BODY', json.dumps(fallback.get('extra', {}) if shared else {})))
    if not isinstance(extra, dict) or set(extra) & {'model', 'messages', 'tools', 'stream', 'api_key'}:
        raise ValueError('Extra model parameters must not replace request identity or credentials')
    return {'name': 'openai/' + wire, 'wire': wire, 'base': base, 'key_env': key_env,
            'returned': os.environ.get(f'{role}_RESPONSE_MODEL', fallback.get('returned', wire) if shared else wire),
            'extra': extra, 'tool_schema_mode': os.environ.get(f'{role}_TOOL_SCHEMA_MODE')}


def llm_arguments(model):
    return {'api_base': model['base'], 'extra_body': model['extra'], 'temperature': 0,
            'top_p': 1, 'max_tokens': 4096, 'stream': False, 'num_retries': 2, 'timeout': 240}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('results'))
    parser.add_argument('--tasks', nargs='+', type=int, default=list(range(50)))
    parser.add_argument('--concurrency', type=int, default=3)
    args = parser.parse_args()
    if args.concurrency < 1 or len(args.tasks) != len(set(args.tasks)) or any(t not in range(50) for t in args.tasks):
        parser.error('Use positive concurrency and unique Airline task IDs from 0 to 49')
    if args.output.exists():
        parser.error('Choose a new output directory to preserve existing results')
    data = Path(os.environ.get('TAU2_DATA_DIR', '')).resolve()
    db = data / 'tau2/domains/airline/db.json'
    if not db.is_file():
        parser.error('Set TAU2_DATA_DIR to the installed benchmark data directory')
    expected = {
        'tau2/domains/airline/db.json': '1af9fea6e03ca7ca15a22bb3fcaf3e351393e3fc9070b6777947da8996f7531b',
        'tau2/domains/airline/tasks.json': '202f0cdb1cf4bc20b8a3284f00e212882a8dda8eaab81d1d69a5dd9676911ebe',
        'tau2/domains/airline/policy.md': '10dc0525421521208be39cee235bba84a16e2bcba9899eb93d92cd81d2f62fc4',
        'tau2/user_simulator/simulation_guidelines.md': '05f4f48e5beefcb527d81fdee6271ce0e997fa4721e8d3ae4db0e820fb0a9013',
    }
    for relative, digest in expected.items():
        path = data / relative
        if not path.is_file() or hashlib.sha256(path.read_text(encoding='utf-8').encode()).hexdigest() != digest:
            parser.error('Evaluation data differs from the frozen Airline release; supply the matching external data directory')
    agent = model_settings('AGENT')
    user = model_settings('USER', agent)
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
    os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
    os.environ['LOGURU_LEVEL'] = 'ERROR'
    os.environ['ACG_AIRLINE_DB_PATH'] = str(db)
    from tau2.data_model.message import AssistantMessage
    from tau2.data_model.simulation import TextRunConfig
    from tau2.registry import registry
    from tau2.runner.batch import run_domain
    from tau2.utils import llm_utils
    from acg import transport
    from acg.integrations.tau_airline import create_tau_airline_agent
    original = llm_utils.to_litellm_messages

    def convert(messages):
        converted = original(messages)
        if len(converted) != len(messages):
            return converted
        for source, target in zip(messages, converted):
            if not isinstance(source, AssistantMessage) or not target.get('tool_calls'):
                continue
            raw = source.raw_data
            if not isinstance(raw, dict):
                continue
            choices = raw.get('choices') or []
            body = choices[0].get('message', {}) if choices and isinstance(choices[0], dict) else {}
            calls = {str(c.get('id')): c for c in body.get('tool_calls', []) if isinstance(c, dict)}
            for call in target['tool_calls']:
                extra = calls.get(str(call.get('id')), {}).get('extra_content')
                if isinstance(extra, dict):
                    call['extra_content'] = copy.deepcopy(extra)
        return converted

    routes = {}
    for model in (agent, user):
        route = {'base_url': model['base'], 'wire_model': model['wire'],
                 'key_env': model['key_env'], 'expected_response_model': model['returned'],
                 'tool_schema_mode': model['tool_schema_mode']}
        if model['wire'] in routes and routes[model['wire']] != route:
            raise ValueError('Identical model names must use the same endpoint and credential route')
        routes[model['wire']] = route
    transport.MODEL_ROUTES = routes
    llm_utils.completion = transport.direct_completion
    llm_utils.to_litellm_messages = convert
    registry.register_agent_factory(create_tau_airline_agent, 'acg_airline')
    config = TextRunConfig(domain='airline', task_set_name=None, task_split_name='base',
        task_ids=[str(t) for t in args.tasks], num_trials=1, agent='acg_airline',
        llm_agent=agent['name'], llm_args_agent=llm_arguments(agent),
        user='user_simulator', llm_user=user['name'], llm_args_user=llm_arguments(user),
        max_steps=200, max_errors=10, timeout=None, save_to=str(args.output.resolve()),
        max_concurrency=args.concurrency, workers=0, seed=300, log_level='ERROR', verbose_logs=False,
        max_retries=3, retry_delay=1.0, auto_resume=False, auto_review=False,
        hallucination_retries=3, enforce_communication_protocol=False)
    results = run_domain(config)
    simulations = results.simulations
    failures = {'infrastructure_error', 'unexpected_error', 'timeout'}
    valid = [s for s in simulations
             if getattr(s.termination_reason, 'value', s.termination_reason) not in failures
             and s.reward_info is not None and s.reward_info.reward in {0, 1}]
    summary = {'tasks': len(args.tasks), 'completed': len(valid),
               'successes': sum(s.reward_info.reward == 1 for s in valid),
               'task_success_rate': sum(s.reward_info.reward == 1 for s in valid) / len(args.tasks)}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary))
    complete = len(valid) == len(args.tasks) and {str(s.task_id) for s in valid} == {str(t) for t in args.tasks}
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
