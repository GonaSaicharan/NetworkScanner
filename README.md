# Network Security Scanner (Educational Use Only)

A Python-based network scanner built with Flask that identifies open ports, vulnerabilities, and provides security recommendations.

## ⚠️ Legal Disclaimer
Unauthorized network scanning is illegal. Only use this tool on networks you own or have explicit permission to scan. The developer assumes no responsibility for unauthorized or illegal use of this software. Users are solely responsible for ensuring their scanning activities comply with all applicable laws.

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
