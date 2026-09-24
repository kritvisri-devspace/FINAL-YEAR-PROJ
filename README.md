# SOC Two-Agent Analyzer (prototype)

Detection Agent -> Investigation Agent over security logs, with optional adversarial log injection.

## Run
1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and set `GROQ_API_KEY` (console.groq.com)
3. `python -m uvicorn app.main:app --reload`, then open http://127.0.0.1:8000

To go local later: set `LLM_PROVIDER=ollama` and `LLM_MODEL=llama3.2:3b` in `.env`. No code changes.

Every run stores the exact prompt and output of each agent in `data/runs.db`.
Ground truth is stored for evaluation but never sent to an agent.
