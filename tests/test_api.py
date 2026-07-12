import json
from fastapi.testclient import TestClient
import api_server

client = TestClient(api_server.app)

def mock_ai_summary(df):
    return json.dumps([
        {
            "attack_type": "Brute Force",
            "suspicious_ip": "192.168.1.10",
            "severity": "high",
            "action": "block",
            "confidence": 0.95,
            "explanation": "Multiple failed login attempts detected."
        }
    ])

def test_home_endpoint():
    response = client.get("/")
    assert response.status_code == 200

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200

def test_analyze_logs(monkeypatch):
    monkeypatch.setattr(
        api_server,
        "generate_ai_summary",
        mock_ai_summary
    )

    response = client.post(
        "/analyze",
        json=[
            "Failed login from 192.168.1.10"
        ]
    )

    assert response.status_code == 200