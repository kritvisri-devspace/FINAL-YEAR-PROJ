"""Thin OpenAI-compatible chat client. Groq now, Ollama (local) later: same code path."""
import json
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

PROVIDERS = {
    "groq": "https://api.groq.com/openai/v1",
    "ollama": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
}


class LLMError(Exception):
    pass


def settings() -> dict:
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    default_model = "llama3.2:3b" if provider == "ollama" else "openai/gpt-oss-120b"
    return {
        "provider": provider,
        "model": os.getenv("LLM_MODEL", default_model),
        "has_key": bool(os.getenv("GROQ_API_KEY")) or provider == "ollama",
    }


def chat_json(messages: list[dict], retries: int = 4) -> dict:
    """Call the LLM in JSON mode; return the parsed object. Backs off on rate limits."""
    cfg = settings()
    if cfg["provider"] not in PROVIDERS:
        raise LLMError(f"Unknown LLM_PROVIDER '{cfg['provider']}'")
    headers = {}
    if cfg["provider"] == "groq":
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise LLMError("GROQ_API_KEY is not set. Add it to .env")
        headers["Authorization"] = f"Bearer {key}"

    body = {
        "model": cfg["model"],
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    url = PROVIDERS[cfg["provider"]] + "/chat/completions"
    last = ""
    for attempt in range(retries):
        try:
            r = httpx.post(url, json=body, headers=headers, timeout=120)
        except httpx.HTTPError as e:
            raise LLMError(f"Could not reach LLM provider: {e}") from e
        if r.status_code == 429:
            wait = float(r.headers.get("retry-after", 2 ** attempt * 2))
            last = "rate limited"
            time.sleep(min(wait, 30))
            continue
        if r.status_code >= 400:
            raise LLMError(f"LLM error {r.status_code}: {r.text[:300]}")
        text = r.json()["choices"][0]["message"]["content"]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            last = "invalid JSON from model"
            body["messages"] = messages + [
                {"role": "user", "content": "Your last reply was not valid JSON. Reply with the JSON object only."}
            ]
    raise LLMError(f"LLM failed after {retries} attempts ({last})")
