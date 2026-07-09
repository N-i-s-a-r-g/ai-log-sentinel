import time
from google import genai

def generate_ai_summary(df, api_key):

    client = genai.Client(api_key=api_key)

    logs_text = df.to_string(index=False)

    prompt = f"""
    Analyze logs and detect attacks:
    {logs_text}
    """

    for attempt in range(3):  # 🔁 try 3 times
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            return response.text

        except Exception as e:
            if "503" in str(e):
                time.sleep(3)  # ⏳ wait 3 sec
            else:
                return f"❌ AI Error: {str(e)}"

    return "❌ AI Busy — Try again later"