from parser_engine import parse_log_line


def test_sql_injection_detection():
    log = "2026-07-12 10:30:00 SQL injection attempt from 45.67.89.12"

    result = parse_log_line(log)

    assert result["threat"] == "SQL Injection"
    assert result["score"] == 4
    assert result["level"] == "CRITICAL"
    assert result["ip"] == "45.67.89.12"


def test_xss_detection():
    log = "2026-07-12 10:35:00 XSS attack using <script> from 10.0.0.5"

    result = parse_log_line(log)

    assert result["threat"] == "XSS Attack"
    assert result["score"] == 3
    assert result["level"] == "WARNING"


def test_brute_force_detection():
    log = "2026-07-12 10:40:00 Failed login from 192.168.1.10"

    result = parse_log_line(log)

    assert result["threat"] == "Brute Force Attempt"
    assert result["score"] == 3
    assert result["ip"] == "192.168.1.10"


def test_normal_log_detection():
    log = "2026-07-12 10:45:00 User logged in successfully from 127.0.0.1"

    result = parse_log_line(log)

    assert result["threat"] == "Normal Activity"
    assert result["score"] == 0
    assert result["level"] == "INFO"


def test_log_without_timestamp():
    log = "Unauthorized access from 8.8.8.8"

    result = parse_log_line(log)

    assert result["timestamp"] == "Unknown"
    assert result["ip"] == "8.8.8.8"
    assert result["threat"] == "Unauthorized Access"