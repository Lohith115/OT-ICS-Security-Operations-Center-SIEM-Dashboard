"""
app.py
Main Flask application.
"""

import os
import logging
from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS

# Import local modules
from database import db_manager
from log_parser import parse_log_line
from correlation_engine import correlation_engine
from anomaly_detector import AnomalyDetector
from datetime import datetime

logger = logging.getLogger(__name__)

# Initialize Anomaly Detector
anomaly_detector = AnomalyDetector()

# Try to train on startup if we have enough logs
try:
    historical_logs = db_manager.get_recent_logs(200)
    if len(historical_logs) >= 10:
        anomaly_detector.train_baseline(historical_logs)
except Exception as e:
    print(f"⚠️ Anomaly detector training skipped: {e}")

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR)
CORS(app)

# --- SECURITY HEADERS FIX ---
@app.after_request
def add_security_headers(response):
    # Allow necessary scripts and styles for Chart.js, Leaflet, and local files
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com https://unpkg.com; "
        "connect-src 'self' https://ip-api.com; "
        "object-src 'none'"
    )
    return response

# --- Frontend Routes ---

@app.route('/')
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    try:
        return send_from_directory(FRONTEND_DIR, filename)
    except FileNotFoundError:
        return "File not found", 404

# --- API Endpoints ---

@app.route('/api/ingest', methods=['POST'])
def ingest_logs():
    try:
        data = request.get_json()
        if not data or 'logs' not in data:
            return jsonify({"error": "No logs provided"}), 400

        raw_logs = data['logs']
        processed_count = 0
        alerts_generated = 0

        for line in raw_logs:
            try:
                parsed_data = parse_log_line(line)
                if parsed_data:
                    log_id = db_manager.insert_log(
                        timestamp=parsed_data['timestamp'],
                        source_ip=parsed_data['source_ip'],
                        log_type=parsed_data['log_type'],
                        severity=parsed_data['severity'],
                        message=parsed_data['message'],
                        raw_log=parsed_data['raw_log']
                    )
                    alert = correlation_engine.analyze_log(parsed_data)
                    if alert:
                        alerts_generated += 1
                processed_count += 1
            except Exception:
                processed_count += 1

        # After processing batch, check for anomalies with ML
        try:
            recent_logs = db_manager.get_recent_logs(30)
            if len(recent_logs) >= 5:
                result = anomaly_detector.detect_anomaly(recent_logs)
                if result['is_anomaly']:
                    db_manager.insert_alert(
                        timestamp=datetime.now().isoformat(),
                        alert_type="ML_ANOMALY",
                        severity="High",
                        source_ip="Multiple",
                        description=f"AI detected anomalous behavior: {result['interpretation']}",
                        related_log_ids=[],
                        mitre_tactic="TA0000 - Unknown",
                        mitre_technique="T0000 - Behavioral Anomaly",
                        risk_score=7.5
                    )
                    alerts_generated += 1
        except Exception as e:
            print(f"ML Anomaly detection error: {e}")

        return jsonify({"status": "success", "processed": processed_count, "alerts_triggered": alerts_generated}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(db_manager.get_recent_logs(limit))

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = request.args.get('limit', 20, type=int)
    return jsonify(db_manager.get_recent_alerts(limit))

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(db_manager.get_stats())

@app.route('/api/alerts/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Updates alert status."""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['NEW', 'IN_PROGRESS', 'RESOLVED']:
            return jsonify({"error": "Invalid status"}), 400
            
        success = db_manager.update_alert_status(alert_id, new_status)
        
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Alert not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', 'False') == 'True')
