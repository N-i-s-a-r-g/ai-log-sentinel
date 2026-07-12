from fastapi import FastAPI
from ai_engine import generate_ai_summary
import pandas as pd
import json

app = FastAPI(
    title="AI Log Sentinel API",
    version="1.0.0"
)


@app.get("/")
def home():
    return {"status": "AI Log Sentinel API running"}


@app.post("/analyze")
def analyze_logs(logs: list[str]):
    try:
        if not logs:
            return {
                "logs_parsed": 0,
                "ai_analysis": [],
                "error": "No logs provided"
            }

        # Convert received logs into a DataFrame
        df = pd.DataFrame({"message": logs})

        # Send DataFrame to AI engine
        summary = generate_ai_summary(df)

        # Convert AI JSON string into Python data
        try:
            ai_json = json.loads(summary)

            # Convert one attack object into a list
            if isinstance(ai_json, dict):
                ai_json = [ai_json]

            # Ensure final format is always a list
            elif not isinstance(ai_json, list):
                ai_json = []

        except (json.JSONDecodeError, TypeError):
            ai_json = [{
                "attack_type": "Unknown",
                "suspicious_ip": "N/A",
                "severity": "low",
                "action": "monitor",
                "confidence": 0,
                "explanation": str(summary)
            }]

        return {
            "logs_parsed": len(logs),
            "ai_analysis": ai_json
        }

    except Exception as error:
        return {
            "logs_parsed": 0,
            "ai_analysis": [],
            "error": str(error)
        }