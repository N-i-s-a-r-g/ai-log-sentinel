from google import genai
import json
import streamlit as st

def generate_ai_summary(df):
    try:
        # 🔑 Streamlit Secrets मधून सुरक्षितपणे की लोड करा
        try:
            api_key = st.secrets["GEMINI_API_KEY"]
        except Exception:
            return json.dumps({
                "attack_type": "Error",
                "suspicious_ip": "0.0.0.0",
                "severity": "high",
                "action": "monitor",
                "confidence": 0,
                "explanation": "🚨 API Key not found in Streamlit Secrets!"
            })

        # ✅ नवीन अधिकृत पद्धतीने क्लायंट इनिशियलाइज करा
        client = genai.Client(api_key=api_key)

        # 🔹 Take last logs (avoid huge input)
        log_sample = df.tail(20).to_string(index=False)

        prompt = f"""
You are a cybersecurity AI.

Analyze the following logs and return ONLY VALID JSON.

LOG DATA:
{log_sample}

FORMAT:
{{
  "attack_type": "string",
  "suspicious_ip": "string",
  "severity": "low | medium | high",
  "action": "monitor | block",
  "confidence": number,
  "explanation": "short human readable explanation"
}}

RULES:
- MUST be valid JSON
- MUST include commas
- NO explanation outside JSON
- NO markdown
- DO NOT add extra text
"""

        # ✅ नवीन लायब्ररीनुसार योग्य मॉडेल कॉल पद्धत
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        output = response.text.strip()

        # 🔥 Remove markdown if exists
        if output.startswith("```"):
            output = output.replace("```json", "").replace("```", "").strip()

        # 🔥 Try parsing JSON
        try:
            parsed = json.loads(output)
            return json.dumps(parsed)
        except Exception:
            # fallback if AI breaks format
            return json.dumps({
                "attack_type": "Unknown",
                "suspicious_ip": "0.0.0.0",
                "severity": "low",
                "action": "monitor",
                "confidence": 50,
                "explanation": "AI output was not in valid JSON format"
            })

    except Exception as e:
        return json.dumps({
            "attack_type": "Error",
            "suspicious_ip": "0.0.0.0",
            "severity": "low",
            "action": "monitor",
            "confidence": 0,
            "explanation": str(e)
        })