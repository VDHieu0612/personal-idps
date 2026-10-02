import sqlite3
import os
import json
import time
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "ids_storage.db")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
EVE_LOG_PATH = os.path.join(LOGS_DIR, "eve.json")
FAST_LOG_PATH = os.path.join(LOGS_DIR, "fast.log")

def append_suricata_logs(alert_dict: Dict[str, Any]):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        ts = alert_dict.get("timestamp", time.time())
        ts_iso = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(ts))
        
        # 1. EVE JSON Format (Standard Suricata / SIEM format)
        eve_record = {
            "timestamp": ts_iso,
            "event_type": "alert",
            "src_ip": alert_dict.get("src_ip"),
            "src_port": alert_dict.get("src_port"),
            "dest_ip": alert_dict.get("dst_ip"),
            "dest_port": alert_dict.get("dst_port"),
            "proto": alert_dict.get("protocol", "TCP"),
            "alert": {
                "action": "alert",
                "signature_id": alert_dict.get("rule_id"),
                "signature": alert_dict.get("rule_name"),
                "category": alert_dict.get("category"),
                "severity": alert_dict.get("severity"),
                "mitre_attack": alert_dict.get("mitre_attack", "")
            }
        }
        with open(EVE_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(eve_record) + "\n")
        
        # 2. Fast Log Format (Snort / Suricata readable one-line log)
        ts_str = time.strftime('%m/%d/%Y-%H:%M:%S', time.localtime(ts))
        fast_line = f"{ts_str}  [**] [{alert_dict.get('rule_id')}] {alert_dict.get('rule_name')} [**] [Category: {alert_dict.get('category')}] [Priority: {alert_dict.get('severity')}] {{{alert_dict.get('protocol')}}} {alert_dict.get('src_ip')}:{alert_dict.get('src_port')} -> {alert_dict.get('dst_ip')}:{alert_dict.get('dst_port')}\n"
        with open(FAST_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(fast_line)
    except Exception as e:
        print(f"[File Log Error]: {e}")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table for network packets summary
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packet_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        length INTEGER,
        info TEXT
    )
    """)
    
    # Table for security alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        rule_id TEXT,
        rule_name TEXT,
        severity TEXT,
        category TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        mitre_attack TEXT,
        description TEXT
    )
    """)
    
    # Table for active blocked IPs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        blocked_at REAL
    )
    """)

    conn.commit()
    conn.close()

def log_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, length: int, info: str = ""):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO packet_logs (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), src_ip, dst_ip, src_port, dst_port, protocol, length, info))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Error] log_packet: {e}")

def create_alert(rule_id: str, rule_name: str, severity: str, category: str, 
                 src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, 
                 mitre_attack: str = "", description: str = ""):
    now_ts = time.time()
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO alerts (timestamp, rule_id, rule_name, severity, category, src_ip, dst_ip, src_port, dst_port, protocol, mitre_attack, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now_ts, rule_id, rule_name, severity, category, src_ip, dst_ip, src_port, dst_port, protocol, mitre_attack, description))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Error] create_alert: {e}")

    # Dual logging: write to Suricata EVE JSON and Fast Log
    append_suricata_logs({
        "timestamp": now_ts,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": category,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "mitre_attack": mitre_attack,
        "description": description
    })

def get_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    now = time.time()
    one_day_ago = now - 86400
    
    cursor.execute("SELECT COUNT(*) FROM packet_logs")
    total_packets = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (one_day_ago,))
    alerts_24h = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    total_blocked = cursor.fetchone()[0]
    
    # Severity stats
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_dist = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Protocol stats
    cursor.execute("SELECT protocol, COUNT(*) FROM packet_logs GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 5")
    protocol_dist = [{"protocol": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    # Top suspicious IPs
    cursor.execute("SELECT src_ip, COUNT(*) as cnt FROM alerts GROUP BY src_ip ORDER BY cnt DESC LIMIT 5")
    top_sources = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "alerts_24h": alerts_24h,
        "blocked_ips_count": total_blocked,
        "severity_distribution": severity_dist,
        "protocol_distribution": protocol_dist,
        "top_suspicious_sources": top_sources
    }

def get_recent_alerts(limit: int = 50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_recent_packets(limit: int = 50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packet_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_blocked_ips():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def toggle_block_ip(ip: str, reason: str = "Manual Admin Block"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips WHERE ip = ?", (ip,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        blocked = False
    else:
        cursor.execute("INSERT INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)", (ip, reason, time.time()))
        blocked = True
    conn.commit()
    conn.close()
    return blocked
