# Authorization Closure Graph: Minimal Repair for LLM Agents with Evolving User Instructions

arxiv: https://arxiv.org/pdf/2609.32428
Implementation of  **ACG**:

- `main.py`: experiment entry point.
- `src/acg/`: authorization graph, repair, confirmation, transport, and Airline integration. Airline specifications are embedded in `airline_spec.py`.

## Run

Use Python 3.12. Install [tau2-bench](https://github.com/sierra-research/tau2-bench) separately at revision `b351ed5f9281d4bdfa5629262f54c8781da0d5be` with `pip install -e .` from its checkout. Its code, data, and license are not bundled here.

Set these environment variables before running:

- `TAU2_DATA_DIR`: the frozen benchmark data directory used for the experiments. The entry point verifies the Airline database, tasks, policy, and user-simulator instructions before making requests.
- `MODEL_BASE_URL`, `MODEL_API_KEY`: your OpenAI-compatible endpoint and credential.
- `AGENT_MODEL`: acting model name.
- `USER_MODEL`: simulator model; defaults to the acting model, using a separate conversation.
- `AGENT_EXTRA_BODY`, `USER_EXTRA_BODY`: provider-specific decoding JSON. For DeepSeek, use `{"thinking":{"type":"disabled"}}`; for GPT, use `{"reasoning_effort":"none"}`.

Optional role-specific settings are `AGENT_BASE_URL`, `USER_BASE_URL`, `AGENT_API_KEY`, and `USER_API_KEY`. Use `AGENT_RESPONSE_MODEL` or `USER_RESPONSE_MODEL` when a provider returns a different model identifier, and `AGENT_TOOL_SCHEMA_MODE=inline_local_refs` if required by the provider.

```bash
python main.py --output results
```

Defaults: all 50 Airline tasks, one trial, seed 300, temperature 0, 200 steps, and concurrency 3. Use `--tasks 0 1` for a small run or `--concurrency 8` to adjust concurrency. The output directory must not already exist. `results.json` contains complete conversations and official rewards; `summary.json` contains task success.
