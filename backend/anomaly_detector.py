"""
anomaly_detector.py
Machine Learning-based anomaly detection
Uses Isolation Forest to detect unusual patterns
This makes your SIEM truly intelligent!
"""

from sklearn.ensemble import IsolationForest
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
import pickle
import os

class AnomalyDetector:
    """
    Detects anomalous behavior using unsupervised ML
    """
    
    def __init__(self, model_path='anomaly_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.baseline_data = []
        self.is_trained = False
        self.feature_history = defaultdict(list)
        
        # Try to load existing model
        if os.path.exists(model_path):
            self.load_model()
    
    def extract_features(self, logs: list) -> np.array:
        """
        Extract numerical features from logs for ML analysis
        
        Features:
        1. Logs per hour
        2. Unique IPs count
        3. Failed attempts ratio
        4. HTTP error ratio
        5. Geographic diversity (unique countries)
        """
        if not logs:
            return np.array([[0, 0, 0, 0, 0]])
        
        # Feature 1: Logs per hour
        logs_per_hour = len(logs)
        
        # Feature 2: Unique IPs
        unique_ips = len(set([log.get('source_ip', '') for log in logs]))
        
        # Feature 3: Failed attempts ratio
        failed = sum(1 for log in logs if 'Failed' in log.get('severity', ''))
        failed_ratio = failed / len(logs) if logs else 0
        
        # Feature 4: HTTP error ratio
        errors = sum(1 for log in logs if log.get('severity') in ['Error', 'Critical'])
        error_ratio = errors / len(logs) if logs else 0
        
        # Feature 5: Geographic diversity (simplified - use length of unique IPs as proxy)
        geo_diversity = min(unique_ips / 10, 1.0)  # Normalize to 0-1
        
        return np.array([[
            logs_per_hour,
            unique_ips,
            failed_ratio,
            error_ratio,
            geo_diversity
        ]])
    
    def train_baseline(self, historical_logs: list):
        """
        Train on normal behavior data
        
        Args:
            historical_logs: List of logs representing normal behavior
        """
        if len(historical_logs) < 10:
            print("⚠️  Need at least 10 log entries to train baseline")
            return
        
        # Extract features from historical data
        # Group logs by hour to get samples
        hourly_groups = self._group_by_hour(historical_logs)
        
        features_list = []
        for hour_logs in hourly_groups:
            if hour_logs:
                features = self.extract_features(hour_logs)
                features_list.append(features[0])
        
        if len(features_list) < 5:
            print("⚠️  Not enough diverse data to train")
            return
        
        # Train Isolation Forest
        X = np.array(features_list)
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X)
        self.is_trained = True
        
        print(f"✅ Trained anomaly detector on {len(features_list)} samples")
        
        # Save model
        self.save_model()
    
    def detect_anomaly(self, recent_logs: list) -> dict:
        """
        Detect if current log pattern is anomalous
        
        Returns:
            Dictionary with anomaly score and details
        """
        if not self.is_trained:
            return {
                "is_anomaly": False,
                "score": 0,
                "message": "Model not yet trained on baseline data"
            }
        
        # Extract features from recent logs
        features = self.extract_features(recent_logs)
        
        # Predict (-1 = anomaly, 1 = normal)
        prediction = self.model.predict(features)[0]
        
        # Get anomaly score (lower = more anomalous)
        score = self.model.score_samples(features)[0]
        
        is_anomaly = (prediction == -1)
        
        # Interpret the anomaly
        interpretation = self._interpret_anomaly(features[0])
        
        return {
            "is_anomaly": is_anomaly,
            "score": float(score),
            "confidence": abs(score) * 100,  # Convert to percentage
            "interpretation": interpretation,
            "message": f"{'⚠️  ANOMALY DETECTED' if is_anomaly else '✅ Normal behavior'}"
        }
    
    def _interpret_anomaly(self, features: np.array) -> str:
        """Explain what makes this anomalous"""
        logs_per_hour, unique_ips, failed_ratio, error_ratio, geo_diversity = features
        
        reasons = []
        
        if logs_per_hour > 100:
            reasons.append(f"Unusually high log volume ({int(logs_per_hour)} logs/hour)")
        
        if unique_ips > 20:
            reasons.append(f"High number of unique IPs ({int(unique_ips)})")
        
        if failed_ratio > 0.5:
            reasons.append(f"High failure rate ({failed_ratio*100:.1f}%)")
        
        if error_ratio > 0.3:
            reasons.append(f"High error rate ({error_ratio*100:.1f}%)")
        
        if geo_diversity > 0.7:
            reasons.append("Diverse geographic sources")
        
        return "; ".join(reasons) if reasons else "Pattern deviates from baseline"
    
    def _group_by_hour(self, logs: list) -> list:
        """Group logs by hour"""
        hourly_buckets = defaultdict(list)
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'])
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_buckets[hour_key].append(log)
            except:
                continue
        
        return list(hourly_buckets.values())
    
    def save_model(self):
        """Save trained model to disk"""
        if self.model:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            print(f"💾 Model saved to {self.model_path}")
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.is_trained = True
            print(f"✅ Loaded existing model from {self.model_path}")
        except:
            print("⚠️  Could not load model")

# Example usage in Flask app:
"""
from anomaly_detector import AnomalyDetector

anomaly_detector = AnomalyDetector()

# Train on first 100 logs (run this once during setup)
historical_logs = db_manager.get_recent_logs(100)
anomaly_detector.train_baseline(historical_logs)

# Check for anomalies (run this periodically or on new logs)
recent_logs = db_manager.get_recent_logs(20)
result = anomaly_detector.detect_anomaly(recent_logs)

if result['is_anomaly']:
    # Generate alert
    db_manager.insert_alert(
        timestamp=datetime.now().isoformat(),
        alert_type="ANOMALY_DETECTED",
        severity="High",
        source_ip="Multiple",
        description=f"ML detected anomalous behavior: {result['interpretation']}",
        related_log_ids=[]
    )
"""

# Installation requirement:
"""
Add to requirements.txt:
scikit-learn>=1.3.0
"""
