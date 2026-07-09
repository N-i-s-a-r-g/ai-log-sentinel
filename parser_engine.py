import re

def parse_log_line(line):
    try:
        # Extract timestamp
        timestamp_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
        timestamp = timestamp_match.group() if timestamp_match else "Unknown"

        # Extract IP
        ip_match = re.search(r"\b\d+\.\d+\.\d+\.\d+\b", line)
        ip = ip_match.group() if ip_match else "0.0.0.0"

        message = line.lower()

        # 🔥 SMART DETECTION (ALL TYPES)
        if any(word in message for word in ["failed", "invalid", "denied", "attempt"]):
            threat = "Brute Force Attempt"
            score = 3

        elif "sql" in message or "injection" in message:
            threat = "SQL Injection"
            score = 4
            level = "CRITICAL"

        elif "xss" in message or "<script>" in message:
            threat = "XSS Attack"
            score = 3
            level = "WARNING"

        elif "error" in message or "unauthorized" in message:
            threat = "Suspicious Activity"
            score = 2
            level = "WARNING"

        else:
            threat = "Normal Activity"
            score = 0
            level = "INFO"
        # 🔥 AUTO LEVEL SYSTEM (ADD THIS)
        if score >= 4:
            level = "CRITICAL"
        elif score >= 2:
            level = "WARNING"
        else:
            level = "INFO"

        return {
            "timestamp": timestamp,
            "level": level,
            "message": line,
            "ip": ip,
            "threat": threat,
            "score": score
        }

    except Exception as e:
        print("Parse error:", e)
        return None