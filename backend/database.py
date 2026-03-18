"""
database.py
SQLite database handler for the SIEM Dashboard.
Handles connection pooling, schema initialization, and CRUD operations
for logs and alerts.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from contextlib import contextmanager


class DatabaseManager:
    """Manages database connections and operations for the SIEM."""

    def __init__(self, db_name: str = "siem.db"):
        self.db_name = db_name
        # Initialize tables upon creation
        self.init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections to ensure they are closed properly."""
        conn = sqlite3.connect(self.db_name)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row  # Allows accessing columns by name
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """
        Initialize the database schema.
        Creates 'logs' and 'alerts' tables if they do not exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table: logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT,
                    log_type TEXT,
                    severity TEXT,
                    message TEXT,
                    raw_log TEXT
                )
            """)


            # Index for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_ip_time 
                ON logs (source_ip, timestamp)
            """)

            # Table: alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    description TEXT,
                    related_logs TEXT,
                    status TEXT DEFAULT 'NEW',
                    latitude REAL,
                    longitude REAL,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    risk_score REAL
                )
            """)
            
            # Migration: Add columns if they don't exist (for existing databases)
            cursor.execute("PRAGMA table_info(alerts)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'mitre_tactic' not in columns:
                cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT")
                cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT")
                cursor.execute("ALTER TABLE alerts ADD COLUMN risk_score REAL")
            
            conn.commit()

    def insert_log(self, timestamp: str, source_ip: str, log_type: str, 
                   severity: str, message: str, raw_log: str) -> int:
        """
        Insert a parsed log entry into the database.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # FIXED: 6 columns match 6 placeholders
            query = """
                INSERT INTO logs (timestamp, source_ip, log_type, severity, message, raw_log)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (timestamp, source_ip, log_type, severity, message, raw_log))
            conn.commit()
            return cursor.lastrowid

    def insert_alert(self, timestamp: str, alert_type: str, severity: str, 
                     source_ip: str, description: str, related_log_ids: List[int],
                     latitude: float = None, longitude: float = None,
                     mitre_tactic: str = None, mitre_technique: str = None, 
                     risk_score: float = None) -> int:
        """
        Insert a security alert into the database.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            related_logs_json = json.dumps(related_log_ids)
            
            query = """
                INSERT INTO alerts (timestamp, alert_type, severity, source_ip, description, 
                                 related_logs, latitude, longitude, mitre_tactic, 
                                 mitre_technique, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (timestamp, alert_type, severity, source_ip, description, 
                                 related_logs_json, latitude, longitude, mitre_tactic, 
                                 mitre_technique, risk_score))
            conn.commit()
            return cursor.lastrowid

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve the most recent logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve the most recent alerts with MITRE data."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, source_ip, description, 
                       related_logs, status, latitude, longitude, 
                       mitre_tactic, mitre_technique, risk_score 
                FROM alerts 
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def count_failed_attempts(self, ip_address: str, minutes: int = 5) -> int:
        """Count failed SSH attempts for a specific IP within a time window."""
        time_threshold = datetime.now() - timedelta(minutes=minutes)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT COUNT(id) 
                FROM logs 
                WHERE source_ip = ? 
                AND log_type = 'SSH' 
                AND severity = 'Failed' 
                AND timestamp >= ?
            """
            cursor.execute(query, (ip_address, time_threshold))
            count = cursor.fetchone()[0]
            return count
    
    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Updates the status of an alert (NEW, IN_PROGRESS, RESOLVED)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            conn.commit()
            return cursor.rowcount > 0

    def count_404_errors(self, ip_address: str, minutes: int = 5) -> int:
        """Count 404 HTTP status codes for a specific IP within a time window."""
        time_threshold = datetime.now() - timedelta(minutes=minutes)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT COUNT(id) 
                FROM logs 
                WHERE source_ip = ? 
                AND log_type = 'HTTP' 
                AND message LIKE '%404%'
                AND timestamp >= ?
            """
            cursor.execute(query, (ip_address, time_threshold))
            count = cursor.fetchone()[0]
            return count
            
    def get_stats(self) -> Dict[str, Any]:
        """Calculate dashboard statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total Logs
            cursor.execute("SELECT COUNT(*) FROM logs")
            stats['total_logs'] = cursor.fetchone()[0]
            
            # Total Alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            # Top Attacker IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as count 
                FROM alerts 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 5
            """)
            stats['top_attackers'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
            stats['alerts_by_status'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            return stats

# --- IMPORTANT ---
# This line must be at the top level (unindented) to be importable.
# It creates the database file and tables immediately.
db_manager = DatabaseManager()
