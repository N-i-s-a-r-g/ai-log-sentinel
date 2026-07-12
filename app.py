import json
import requests
import re
import time
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from parser_engine import parse_log_line
from database import init_db, insert_log, fetch_logs
from alert_engine import send_email_alert
from block_engine import auto_block_ips
# AI optional
try:
    from ai_engine import generate_ai_summary
    AI_AVAILABLE = True
except:
    AI_AVAILABLE = False

st.set_page_config(page_title="AI Log Sentinel", layout="wide")

st.title("🛡️ AI-Powered Log Sentinel")
init_db()
st.markdown("""
### 🔍 Features:
- 🚨 Real-time Threat Detection
- 🤖 AI-based Anomaly Detection
- 📧 Email Alert System
- 📊 Attack Visualization
- 🧠 Attack Intelligence Panel
""")

st.info("""
This system analyzes log files to detect cyber threats such as brute force attacks,
SQL injection attempts, and unusual activity using machine learning.
""")

st.write("Threat Detection Dashboard")
st.markdown("---")
user_email = st.text_input("📧 Enter your email for alerts")
uploaded_file = st.file_uploader("Upload log file", type=["txt"])
mode = st.radio("Select Mode", ["Upload Logs", "Real-Time Monitoring"])

if uploaded_file:
    lines = uploaded_file.read().decode().splitlines()
    parsed_data = []

    for line in lines:
        result = parse_log_line(line)

    # 🔍 DEBUG PRINTS (ADD THIS)
        print("LINE:", line)
        print("PARSED:", result)

        if result:
            parsed_data.append(result)
            insert_log(result)
            
    df = pd.DataFrame(parsed_data)
    
    if mode == "Real-Time Monitoring":
        st.warning("⚡ Real-Time Monitoring Mode (Simulated)")

        for i in range(3):
            st.write(f"🔴 Live analyzing logs... ({i+1})")
            time.sleep(1)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df.empty or "threat" not in df.columns:
        st.warning("⚠️ Logs not parsed correctly or unsupported format")
        st.stop()

    # 🔹 METRICS
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", len(df))
    col2.metric("Threats", len(df[df["threat"] != "Normal Activity"]))
    col3.metric("Critical Alerts", len(df[df["level"] == "CRITICAL"]))

    st.markdown("### 📊 Parsed Logs")
    st.dataframe(df)
    filter_option = st.selectbox(
        "Filter Logs",
        ["All", "Only Threats", "Only Normal"]
    )

    if filter_option == "Only Threats":
        df_display = df[df["score"] > 0]
    elif filter_option == "Only Normal":
        df_display = df[df["score"] == 0]
    else:
        df_display = df

    st.dataframe(df_display)
    st.markdown("### 🚨 Only Threat Logs")
    threat_df = df[df["score"] > 0]
    st.dataframe(threat_df)
    st.markdown("### 📥 Download Logs")
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Logs as CSV",
        data=csv,
        file_name="log_analysis.csv",
        mime="text/csv"
    )

    # 🔹 THREAT SCORE
    st.markdown("### ⚡ Threat Score")
    total_score = df["score"].sum() if "score" in df.columns else 0
    st.markdown("### 🚨 Threat Level Meter")

    if total_score > 10:
        st.progress(100)
    elif total_score > 5:
        st.progress(60)
    else:
        st.progress(20)
    if total_score > 10:
        st.error(f"🔥 HIGH RISK SYSTEM ({total_score})")
    elif total_score > 5:
        st.warning(f"⚠️ MEDIUM RISK ({total_score})")
    else:
        st.success(f"✅ LOW RISK ({total_score})")
    st.markdown("### 🧠 System Verdict")

    if total_score > 15:
        st.error("🚨 System Under Active Attack")

    elif total_score > 5:
        st.warning("⚠️ Suspicious Activity Detected")

    else:
        st.success("✅ System Safe")

    # 🛡️ Attack Response System
    st.markdown("### 🛡️ Attack Response System")
    if total_score > 15:
        st.error("🚨 SYSTEM UNDER ATTACK → IMMEDIATE ACTION REQUIRED")

    elif total_score > 5:
        st.warning("⚠️ Suspicious Activity → Monitor Closely")

    else:
        st.success("✅ System Stable")

    # 🔹 Suspicious IP Detection
    attack_counts = df[df["threat"] == "Brute Force Attempt"]["ip"].value_counts()
    suspicious_ips = attack_counts[attack_counts >= 3]
    # 🚫 AUTO BLOCK SYSTEM
    st.markdown("### 🚫 Auto Block System")

    blocked_ips = auto_block_ips(df)

    if not blocked_ips.empty:
        st.error("🚨 Auto-Blocked IPs (High Risk)")
        st.write(blocked_ips)

        # Save to file
        blocked_ips.to_csv("blocked_ips.csv")

    else:
        st.success("✅ No IPs blocked")

    # 🔹 ML ANOMALY DETECTION
    st.markdown("### 🧠 AI Anomaly Detection")
    try:
        model_df = df[["score"]]
        model = IsolationForest(contamination=0.2)
        model.fit(model_df)
        df["anomaly"] = model.predict(model_df)

        anomalies = df[df["anomaly"] == -1]

        if not anomalies.empty:
            st.error("🚨 Anomalies Detected!")
            st.dataframe(anomalies)
        else:
            st.success("✅ No anomalies detected")

    except:
        st.warning("ML module error")

    # 🔹 ALERT SYSTEM
    st.markdown("### 🚨 Real-Time Alerts")

    alerts = []

    if total_score > 10:
        alerts.append("🔥 High Risk System Detected!")

    if not suspicious_ips.empty:
        alerts.append("⚠️ Multiple login attempts from same IP!")

    if "anomaly" in df.columns and (df["anomaly"] == -1).any():
        alerts.append("🤖 AI detected unusual activity!")

    if alerts:
        for alert in alerts:
            st.error(alert)
    if "last_email_sent" not in st.session_state:
        st.session_state.last_email_sent = False

    if alerts and not st.session_state.last_email_sent:
        if user_email:
            send_email_alert("\n".join(alerts), user_email)
            st.session_state.last_email_sent = True

    st.markdown("### 📄 Generate Attack Report")
    if st.button("Generate Report"):

        report = f"""
        🔐 AI Log Sentinel Report

        Total Logs: {len(df)}
        Total Threats: {len(df[df['score'] > 0])}
        Total Risk Score: {total_score}

        Most Dangerous IP:
        {df.groupby("ip")["score"].sum().idxmax()}

        Most Common Threat:
        {df['threat'].value_counts().idxmax()}
        """

        st.text_area("Report", report)
    # 🔹 Brute Force Display
    st.markdown("### 🚨 Suspicious IP Detection")

    if not suspicious_ips.empty:
        st.error("⚠️ Potential Brute Force Attack Detected!")
        st.write(suspicious_ips)
    else:
        st.success("No major brute force attacks detected")

    # 🔹 Most Dangerous IP
    st.markdown("### 🎯 Most Dangerous IP")
    danger_ip = df.groupby("ip")["score"].sum().sort_values(ascending=False)
    st.write(danger_ip.head(3))
    
    # Define threshold
    BLACKLIST_THRESHOLD = 5
    # Calculate IP risk
    ip_risk = df.groupby("ip")["score"].sum()

    # Blacklist logic
    blacklisted_ips = ip_risk[ip_risk >= BLACKLIST_THRESHOLD]
    st.markdown("### 🚫 Blacklisted IPs")
    if not blacklisted_ips.empty:
        st.error("🚫 Blacklisted IPs Detected!")
        st.write(blacklisted_ips)
        st.download_button(
            "Download Blacklist",
            blacklisted_ips.to_csv().encode("utf-8"),
            "blacklist.csv",
            "text/csv"
        )
    else:
        st.success("✅ No IPs blacklisted")
    st.markdown("### 🔥 IP Risk Score")

    ip_risk = df.groupby("ip")["score"].sum().sort_values(ascending=False)

    st.dataframe(ip_risk)
    top_ip = df.groupby("ip")["score"].sum().idxmax()
    st.error(f"🚨 Most Dangerous IP: {top_ip}")

    # 🔹 Pie Chart
    st.markdown("### 📊 Threat Distribution")
    threat_counts = df["threat"].value_counts()

    fig1, ax1 = plt.subplots()
    ax1.pie(threat_counts, labels=threat_counts.index, autopct='%1.1f%%')
    ax1.axis('equal')
    st.pyplot(fig1)
    st.markdown("### 📊 Threat Breakdown")

    st.bar_chart(df["threat"].value_counts())

    # 🔹 Bar Chart
    st.markdown("### 📈 Top Attacker IPs")
    ip_counts = df[df["threat"] != "Normal Activity"]["ip"].value_counts()
    st.bar_chart(ip_counts)
    st.markdown("### 🧠 Attack Intelligence")

    st.markdown("### 🌍 Attack Location Map")
    locations = []

    for ip in df["ip"].unique():
        try:
            res = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5,
            )
            res.raise_for_status()
            data = res.json()

            if "loc" in data:
                lat, lon = map(float, data["loc"].split(","))
                locations.append({"lat": lat, "lon": lon})

        except:
            pass

    # Convert to DataFrame
    if locations:
        map_df = pd.DataFrame(locations)
        st.map(map_df)
    else:
        st.warning("No location data available")

    # Total unique attackers
    unique_ips = df["ip"].nunique()
    st.write(f"🔹 Unique Attackers: {unique_ips}")

    # Most common attack type
    top_threat = df["threat"].value_counts().idxmax()
    st.write(f"🔹 Most Common Attack: {top_threat}")

    # Peak attack hour
    if "timestamp" in df.columns:
        peak_hour = df["timestamp"].dt.hour.value_counts().idxmax()
        valid_timestamps = df["timestamp"].dropna()
        if not valid_timestamps.empty:
            hourly_counts = valid_timestamps.dt.hour.value_counts()
            peakhour = hourly_counts.idxmax()
            st.write(f"🔹 Peak Attack Hour: {peak_hour}:00")
        else:
            st.info("No valid timestamps available for peak-hour analysis")
    # 🔹 Timeline
    st.markdown("### ⏱️ Attack Timeline")

    valid_timestamps = df["timestamp"].dropna()

    if not valid_timestamps.empty:
        timeline_df = df[df["timestamp"].notna()].copy()
        timeline = timeline_df.groupby(
            timeline_df["timestamp"].dt.hour
        )["score"].sum()

        st.line_chart(timeline)
    else:
        st.info("No valid timestamps available for timeline")

    # 🔹 AI (optional)
    if AI_AVAILABLE:
        st.markdown("### 🤖 AI Threat Analysis")

        try:
            with st.spinner("AI Agent analyzing..."):

                logs_list = df["message"].tolist()

                api_url = st.secrets.get(
                    "FASTAPI_URL",
                    "http://127.0.0.1:8000"
                )

                response = requests.post(
                    f"{api_url}/analyze",
                    json=logs_list,
                    timeout=45
                )

                response.raise_for_status()

                data = response.json()
                ai_result = data.get("ai_analysis", [])

                # 🔥 HANDLE STRING JSON
                if isinstance(ai_result, str):
                    try:
                        ai_result = json.loads(ai_result)
                    except:
                        st.warning("⚠️ AI returned plain text")
                        st.write(ai_result)
                        ai_result = []

                # ✅ SAFE PROCESSING
                if isinstance(ai_result, list):

                    for item in ai_result:
                        attack_type = item.get("attack_type") or "Unknown"
                        ip = item.get("suspicious_ip") or "N/A"
                        severity = (item.get("severity") or "low").lower()
                        action = (item.get("action") or "monitor").lower()
                        explanation = item.get("explanation") or "No explanation"

                        confidence = item.get("confidence", 0)
                        if confidence <= 1:
                            confidence = int(confidence * 100)
                        else:
                            confidence = int(confidence)

                        st.markdown("### 🧠 AI Decision Summary")

                        st.write(f"Attack Type: {attack_type}")
                        st.write(f"Suspicious IP: {ip}")
                        st.write(f"Severity: {severity.upper()}")
                        st.write(f"Action: {action.upper()}")
                        st.write(f"Confidence: {confidence}%")

                        st.markdown("### 📘 Explanation")
                        st.info(explanation)

                        # 🎯 Severity UI
                        if severity == "high":
                            st.error(f"🚨 HIGH THREAT from {ip}")
                        elif severity == "medium":
                            st.warning(f"⚠️ MEDIUM THREAT from {ip}")
                        else:
                            st.success("✅ LOW RISK")

                        # 🚫 BLOCK
                        if action == "block" and ip != "N/A":
                            with open("ai_blocked_ips.txt", "a+") as f:
                                f.seek(0)
                                existing = f.read()

                                if ip not in existing:
                                    f.write(ip + "\n")

                            st.error(f"🚫 AI BLOCKED IP: {ip}")

                else:
                    st.warning("⚠️ Unexpected AI format")

        except Exception as ai_err:
            st.warning(f"AI Error: {str(ai_err)}")
    # 🔹 DATABASE
    st.markdown("### 💾 Stored Logs (Database)")
    stored = fetch_logs()
    df_db = pd.DataFrame(stored, columns=["timestamp", "level", "message", "ip", "threat"])
    st.dataframe(df_db)

else:
    st.info("Upload a log file to start")