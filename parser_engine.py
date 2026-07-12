import re


def parse_log_line(line: str):
    try:
        timestamp_match = re.search(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            line
        )
        timestamp = timestamp_match.group() if timestamp_match else "Unknown"

        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line
        )
        ip = ip_match.group() if ip_match else "0.0.0.0"

        message = line.lower()

        # Specific attacks must be checked first
        if "sql" in message or "injection" in message:
            threat = "SQL Injection"
            score = 4

        elif "xss" in message or "<script>" in message:
            threat = "XSS Attack"
            score = 3

        elif any(
            phrase in message
            for phrase in [
                "failed login",
                "failed password",
                "invalid password",
                "login attempt",
                "multiple login",
                "authentication failed",
            ]
        ):
            threat = "Brute Force Attempt"
            score = 3

        elif "unauthorized" in message or "access denied" in message:
            threat = "Unauthorized Access"
            score = 2

        elif "error" in message:
            threat = "Suspicious Activity"
            score = 2

        else:
            threat = "Normal Activity"
            score = 0

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
            "score": score,
        }

    except Exception as error:
        print("Parse error:", error)
        return None