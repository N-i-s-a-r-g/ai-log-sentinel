import json
import os

import streamlit as st
from google import genai


def get_api_key() -> str:
    # First try Streamlit Secrets
    try:
        key = st.secrets.get("GEMINI_API_KEY")
        if key:
            return str(key)
    except Exception:
        pass

    # Then try environment variable for FastAPI deployment
    key = os.getenv("GEMINI_API_KEY")

    if not key:
        raise RuntimeError(
            "GEMINI_API_KEY was not found in Streamlit Secrets "
            "or environment variables."
        )

    return key


def generate_ai_summary(df) -> str:
    try:
        api_key = get_api_key()
        client = genai.Client(api_key=api_key)

        log_sample = df.tail(20).to_string(index=False)

        prompt = f"""
You are a cybersecurity threat-analysis assistant.

Analyze every relevant log line and return ONLY a valid JSON array.

LOG DATA:
{log_sample}

Each array item must follow this structure:

[
  {{
    "attack_type": "string",
    "suspicious_ip": "string",
    "severity": "low, medium, or high",
    "action": "monitor or block",
    "confidence": 0.0,
    "explanation": "short human-readable explanation"
  }}
]

Rules:
- Return a JSON array even when only one attack is found.
- Confidence must be between 0 and 1.
- Do not include Markdown.
- Do not include text outside the JSON.
- Do not invent an IP address.
- Ignore normal activity unless it helps explain an attack.
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        output = (response.text or "").strip()

        if output.startswith("```"):
            output = (
                output
                .replace("```json", "")
                .replace("```JSON", "")
                .replace("```", "")
                .strip()
            )

        parsed = json.loads(output)

        if isinstance(parsed, dict):
            parsed = [parsed]

        if not isinstance(parsed, list):
            raise ValueError("Gemini did not return a JSON list.")

        return json.dumps(parsed)

    except Exception as error:
        return json.dumps([{
            "attack_type": "AI Engine Error",
            "suspicious_ip": "N/A",
            "severity": "low",
            "action": "monitor",
            "confidence": 0,
            "explanation": str(error),
        }])