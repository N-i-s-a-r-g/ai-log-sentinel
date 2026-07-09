import requests
import streamlit as st

def send_email_alert(message, receiver_email):

    api_key = st.secrets["RESEND_API_KEY"]

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    data = {
        "from": "onboarding@resend.dev",
        "to": receiver_email,
        "subject": "🚨 Security Alert",
        "html": f"<p>{message}</p>"
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        print("✅ Email sent")
    else:
        print("❌ Email failed", response.text)