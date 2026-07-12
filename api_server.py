import json

import pandas as pd
from fastapi import FastAPI, HTTPException

from ai_engine import generate_ai_summary


app = FastAPI(
    title="AI Log Sentinel API",
    description="AI-powered cybersecurity log analysis API",
    version="1.0.0",
)


@app.get("/")
def home():
    return {
        "status": "AI Log Sentinel API running",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze_logs(logs: list[str]):
    if not logs:
        raise HTTPException(
            status_code=400,
            detail="No logs provided",
        )

    clean_logs = [
        log.strip()
        for log in logs
        if isinstance(log, str) and log.strip()
    ]

    if not clean_logs:
        raise HTTPException(
            status_code=400,
            detail="No valid log lines provided",
        )

    try:
        df = pd.DataFrame({"message": clean_logs})
        summary = generate_ai_summary(df)

        try:
            ai_json = json.loads(summary)
        except (json.JSONDecodeError, TypeError):
            ai_json = [{
                "attack_type": "Unknown",
                "suspicious_ip": "N/A",
                "severity": "low",
                "action": "monitor",
                "confidence": 0,
                "explanation": str(summary),
            }]

        if isinstance(ai_json, dict):
            ai_json = [ai_json]

        if not isinstance(ai_json, list):
            ai_json = []

        return {
            "logs_parsed": len(clean_logs),
            "ai_analysis": ai_json,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {error}",
        ) from error