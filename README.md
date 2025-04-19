## README.md
# Network Security Scanner (Educational Use Only)

A Python-based network scanner built with Flask that identifies open ports, vulnerabilities, and provides security recommendations.

## ⚠️ Legal Disclaimer
Unauthorized network scanning is illegal. Only use this tool on networks you own or have explicit permission to scan.

## 🛠 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser to:
```
http://localhost:5000
```

3. Enter a target (IP/hostname) and ports to scan (or use defaults)

4. View results on the dashboard

## 📌 Recommended Test Targets
- `scanme.nmap.org` (with permission)
- Your local network devices (192.168.x.x)

## ⚙️ Configuration
Create a `.env` file for environment variables (optional):
```
# Example .env
DEBUG=True
```

## 📊 Features
- Port scanning with service detection
- Vulnerability assessment
- Threat intelligence
- Risk scoring
- Mitigation recommendations
- Interactive dashboard
```

---

# Task 3: Libraries and Requirements

## Libraries Used:

### app.py:
- flask
- flask_limiter
- logging
- datetime
- asyncio
- os
- python-dotenv
- socket
- time
- ipaddress
- numpy
- scikit-learn (IsolationForest)
- atexit

### dashboard.html:
- plotly.js (loaded from CDN)

### home.html:
- (No external libraries, just HTML/CSS/JS)

## requirements.txt

```
flask==2.3.2
flask-limiter==2.8.1
python-dotenv==1.0.0
numpy==1.24.3
scikit-learn==1.3.0
ipaddress==1.0.23
gunicorn==20.1.0
```

Note: The web templates use Plotly.js which is loaded from CDN, so no Python package is needed for it.
