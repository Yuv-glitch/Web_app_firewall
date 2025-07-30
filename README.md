# 🛡️ Custom Python Web application Firewall

This project is a powerful, lightweight Web Application Firewall built in Python. It operates as a reverse proxy to inspect incoming HTTP requests for malicious payloads, protect web applications from common threats, and harden security through header injection. It is designed to be a simple, effective, and educational tool for understanding the core principles of web security.

---

## ✅ Features
- **Reverse Proxy Architecture**: Sits between the user and your application, ensuring all traffic is inspected before it reaches your server.
- **SQL Injection (SQLi) Detection**: Uses signature-based analysis to detect and block common SQL injection patterns.
- **Heuristic XSS Detection**: Implements a sophisticated scoring system that analyzes request headers, URLs, and body payloads for XSS-related keywords, minimizing false positives.
- **Active Threat Response**: Automatically issues a temporary IP ban to attackers who exceed a configured threat score, blocking malicious scanners and persistent attackers.
- **Security Header Injection**: Hardens the web application's security posture by injecting crucial security headers into the response (e.g., Content-Security-Policy, X-XSS-Protection, Strict-Transport-Security).
- **IP Rate Limiting**: Protects against brute-force attacks and application-layer Denial-of-Service (DoS) by limiting the number of requests a single IP can make in a given time frame.
- **Comprehensive JSON Logging**: Logs all blocked requests with detailed information (Source IP, User-Agent, Full Request Body, Headers etc) in a structured JSON format.

---

## ⚙️ How It Works

The WAF acts as an intermediary server. Every request sent to your web application is first received by WAF. It then passes through a series of security modules before being forwarded to the backend application.
- Request Received: The WAF listens for incoming HTTP requests on a specified port.
- IP Check: It first checks if the source IP is on the temporary ban list or has exceeded the rate limit. If so, the request is dropped immediately.
- Security Inspection: The request is passed to the detection engine, which runs several checks:
  Checking for specific keywords commonly found in SQLi attacks and XSS attacks and creating a score
  Decision Engine: Based on the inspection results, a decision is made:
        ALLOW: If the request is clean, it is forwarded to the backend web application.
        BLOCK & LOG: If the request is deemed malicious, it is blocked. The full request details are logged to incidents.json.
        BLOCK, LOG & BAN: If the threat score surpasses a high-level threshold, the source IP is added to a temporary ban list in addition to being blocked and logged.
 - Response Handling: The response from the backend application is captured by the WAF.
 - Header Injection: The WAF injects pre-configured security headers into the response before sending it back to the original client.
---

## 🚀 Getting Started

### 🔗 **Prerequisites**
- Windows
- Python 3.8+

### 🗂️ **Installation**

```bash

# Run the server
python server.py

# Run the web application firewall
python app.py

# To see the page enter "127.0.0.1:8888" in your browser
```
## ⭐ Final Words
- This project was created as more of a learning project -- PRs, ideas, improvements are welcome!
- Contact me on [Linkedin](https://www.linkedin.com/in/yuvraj-dudhal-0288a3248/)
- Made with :heart: in Python
