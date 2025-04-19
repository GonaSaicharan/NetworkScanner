from flask import Flask, request, jsonify, render_template, url_for, session, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from datetime import datetime
import asyncio
import os
from dotenv import load_dotenv
import socket
import time
import numpy as np
from sklearn.ensemble import IsolationForest
import atexit

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Random secret key for sessions


# Cleanup function
def cleanup():
    session.clear()
    print("All scan data cleared")


# Register cleanup
atexit.register(cleanup)

DEFAULT_PORTS = [21, 22, 80, 443, 3306, 3389, 5432, 8080, 8000, 8888]
MAX_PORTS = 100
SCAN_TIMEOUT = 1.0

limiter = Limiter(
    app=app,
    key_func=lambda: request.args.get('api_key', get_remote_address()),
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def validate_target(target):
    try:
        if target.replace('.', '').isdigit():
            ipaddress.ip_address(target)
        else:
            socket.gethostbyname(target)
        return True
    except (ValueError, socket.gaierror):
        return False


def get_service_name(port):
    services = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
        143: 'imap', 443: 'https', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 8080: 'http-proxy', 8000: 'http-alt'
    }
    return services.get(port, f'port-{port}')


async def async_check_port(host, port):
    start_time = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            result = s.connect_ex((host, port))
            return {
                'port': port,
                'status': 'open' if result == 0 else 'closed',
                'service': get_service_name(port),
                'response_time_ms': round((time.time() - start_time) * 1000, 2)
            }
    except Exception as e:
        return {
            'port': port,
            'status': 'error',
            'error': str(e),
            'service': 'unknown',
            'response_time_ms': round((time.time() - start_time) * 1000, 2)
        }


def predict_vulnerabilities(open_ports):
    vuln_rules = {
        21: 'MEDIUM', 22: 'HIGH', 80: 'LOW',
        443: 'MEDIUM', 3306: 'CRITICAL', 3389: 'HIGH'
    }
    return [{'port': p['port'], 'risk': vuln_rules.get(p['port'], 'LOW')}
            for p in open_ports]


def detect_anomalies(scan_results):
    if not scan_results:
        return []

    X = np.array([
        [p['port'], p.get('response_time_ms', 0),
         1 if p.get('status') == 'open' else 0]
        for p in scan_results
    ])
    model = IsolationForest(contamination=0.01)
    anomalies = model.fit_predict(X)
    return [scan_results[i] for i in range(len(anomalies)) if anomalies[i] == -1]


def get_threat_intel(open_ports):
    threats_db = {
        21: [{"id": "T1190", "name": "FTP Exploit"}],
        22: [{"id": "T1110", "name": "SSH Brute Force"}],
        80: [{"id": "T1190", "name": "HTTP Exploit"}],
        443: [{"id": "T1190", "name": "HTTPS Exploit"}],
        3306: [{"id": "T1213", "name": "MySQL Attack"}],
        3389: [{"id": "T1021", "name": "RDP Attack"}]
    }
    return [
        {'port': port['port'], **threat}
        for port in open_ports
        for threat in threats_db.get(port['port'], [])
    ]


def generate_mitigation_advice(vulnerabilities, open_ports):
    if not vulnerabilities:
        max_risk = 'LOW'
    else:
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        max_risk = max(vulnerabilities, key=lambda x: risk_levels.index(x['risk']))['risk']

    advice = {
        'CRITICAL': [
            "Immediate action required!",
            "Disable these services if not needed: " + ", ".join(str(p['port']) for p in open_ports),
            "Implement firewall rules to restrict access",
            "Update all software to latest versions",
            "Monitor for suspicious activity"
        ],
        'HIGH': [
            "Urgent attention needed",
            "Close unnecessary ports: " + ", ".join(str(p['port']) for p in open_ports),
            "Implement strong authentication",
            "Review access controls",
            "Schedule immediate patching"
        ],
        'MEDIUM': [
            "Recommended actions:",
            "Review port configurations",
            "Enable logging for these services",
            "Consider closing unused ports",
            "Update related software"
        ],
        'LOW': [
            "General recommendations:",
            "Keep systems updated",
            "Monitor these services: " + ", ".join(str(p['port']) for p in open_ports),
            "Review security policies",
            "Regular vulnerability scanning recommended"
        ]
    }

    return {
        'risk_level': max_risk,
        'recommendations': advice.get(max_risk, advice['LOW'])
    }


def parse_ports(ports_arg):
    ports = set()
    if ports_arg:
        for part in ports_arg.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if not (0 < start <= 65535 and 0 < end <= 65535):
                        return ({'error': 'Ports must be between 1-65535'}, 400)
                    ports.update(range(start, end + 1))
                except ValueError:
                    return ({'error': 'Invalid port range format'}, 400)
            elif part.isdigit():
                if 0 < int(part) <= 65535:
                    ports.add(int(part))
                else:
                    return ({'error': 'Ports must be between 1-65535'}, 400)
    else:
        ports = set(DEFAULT_PORTS)
    return sorted(ports)[:MAX_PORTS]


async def perform_scan(target, ports):
    tasks = [async_check_port(target, port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/scan', methods=['GET', 'POST'])
@limiter.limit("10/minute")
async def scan():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        ports = request.form.get('ports', '')
    else:
        target = request.args.get('target', '').strip()
        ports = request.args.get('ports', '')

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        if not target:
            return render_template('home.html', error='Target is required')

        if not validate_target(target):
            return render_template('home.html', error='Invalid target')

        parsed_ports = parse_ports(ports)
        if isinstance(parsed_ports, tuple):
            return render_template('home.html', error=parsed_ports[0]['error'])

        results = await perform_scan(target, parsed_ports)
        open_ports = [r for r in results if r.get('status') == 'open']

        analysis = {
            'vulnerabilities': predict_vulnerabilities(open_ports),
            'threats': get_threat_intel(open_ports),
            'mitigation': generate_mitigation_advice(predict_vulnerabilities(open_ports), open_ports),
            'threat_score': min(100, len(open_ports) * 10 +
                                sum(1 for v in predict_vulnerabilities(open_ports)
                                    if v['risk'] in ['HIGH', 'CRITICAL']) * 5)
        }

        session['scan_data'] = {
            'target': '[REDACTED]',
            'results': results,
            'analysis': analysis,
            'scan_id': scan_id,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
        }

        return redirect(url_for('dashboard'))

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return render_template('home.html', error=str(e))


@app.route('/clear-scan')
def clear_scan():
    session.pop('scan_data', None)
    return redirect(url_for('home'))


@app.route('/dashboard')
def dashboard():
    if 'scan_data' not in session:
        return redirect(url_for('home'))
    return render_template('dashboard.html', scan_data=session['scan_data'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)