import os
import sys
import time
import requests

if sys.platform.startswith('win'):
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from .db import (
    init_db, get_stats, get_recent_alerts, get_recent_packets,
    get_blocked_ips, toggle_block_ip
)
from .detector import RuleEngine
from .capture import PacketCapturer

app = FastAPI(
    title="Personal IDS/IPS System API",
    description="Real-time Network Intrusion Detection & Prevention Engine",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# Initialize DB & Rule Engine
init_db()
rule_engine = RuleEngine(RULES_DIR)

# Packet handler callback
def on_packet_captured(pkt: dict):
    rule_engine.process_packet(pkt)

# Start Capturer
capturer = PacketCapturer(callback=on_packet_captured)
capturer.start()

# Data models
class RuleToggleModel(BaseModel):
    rule_id: str
    enabled: bool

class RuleSaveModel(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    enabled: bool = True
    condition: Dict[str, Any]
    action: Dict[str, Any]
    mitre_attack: Optional[str] = ""
    tags: Optional[List[str]] = []

class BlockIPModel(BaseModel):
    ip: str
    reason: Optional[str] = "Manual Dashboard Action"

class BulkToggleModel(BaseModel):
    rule_ids: Optional[List[str]] = None
    category: Optional[str] = None
    enabled: bool = True

# --- API ROUTES ---

@app.get("/api/stats")
def api_stats():
    stats = get_stats()
    stats["capturer_mode"] = capturer.get_engine_status()
    stats["active_rules_count"] = len([r for r in rule_engine.rules if r.get("enabled", True)])
    stats["total_rules_count"] = len(rule_engine.rules)
    return stats

@app.get("/api/alerts")
def api_alerts(limit: int = 50):
    return get_recent_alerts(limit=limit)

@app.get("/api/packets")
def api_packets(limit: int = 50):
    return get_recent_packets(limit=limit)

@app.get("/api/rules")
def api_get_rules():
    return rule_engine.rules

@app.post("/api/rules/toggle")
def api_toggle_rule(data: RuleToggleModel):
    rule_engine.toggle_rule(data.rule_id, data.enabled)
    return {"status": "success", "rule_id": data.rule_id, "enabled": data.enabled}

@app.post("/api/rules/bulk-toggle")
def api_bulk_toggle_rules(data: BulkToggleModel):
    rule_engine.bulk_toggle_rules(rule_ids=data.rule_ids, category=data.category, enabled=data.enabled)
    return {"status": "success", "enabled": data.enabled}

class SuricataImportModel(BaseModel):
    content: Optional[str] = None
    use_sample: bool = False

class FetchETCategoryModel(BaseModel):
    category_file: str
    max_rules: int = 50

from .suricata_importer import (
    import_suricata_rules_text, 
    fetch_et_open_category, 
    ET_CATEGORIES, 
    SAMPLE_ET_RULES
)

@app.get("/api/rules/et-categories")
def api_get_et_categories():
    return ET_CATEGORIES

@app.get("/api/rules/suricata-sample")
def api_get_suricata_sample():
    return {"content": SAMPLE_ET_RULES.strip()}

@app.post("/api/rules/fetch-et-category")
def api_fetch_et_category(data: FetchETCategoryModel):
    try:
        raw_text = fetch_et_open_category(data.category_file)
        imported = import_suricata_rules_text(raw_text, RULES_DIR, max_rules=data.max_rules)
        rule_engine.load_rules()
        return {
            "status": "success",
            "category": data.category_file,
            "imported_count": len(imported),
            "rules": imported
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rules/import-suricata")
def api_import_suricata(data: SuricataImportModel):
    text = SAMPLE_ET_RULES if data.use_sample or not data.content else data.content
    imported = import_suricata_rules_text(text, RULES_DIR)
    rule_engine.load_rules()
    return {
        "status": "success",
        "imported_count": len(imported),
        "rules": imported
    }

@app.post("/api/rules")
def api_save_rule(rule: RuleSaveModel):
    filepath = rule_engine.save_rule(rule.dict())
    return {"status": "success", "filepath": filepath}

@app.get("/api/blocked-ips")
def api_get_blocked_ips():
    return get_blocked_ips()

@app.post("/api/blocked-ips/toggle")
def api_toggle_blocked_ip(data: BlockIPModel):
    is_blocked = toggle_block_ip(data.ip, data.reason)
    return {"status": "success", "ip": data.ip, "is_blocked": is_blocked}

@app.get("/api/threat-intel/lookup")
def api_threat_intel(ip: str):
    # Simulated / cached AbuseIPDB Threat Intel lookup endpoint
    # In production, add API key header: {"Key": "YOUR_ABUSEIPDB_KEY"}
    known_malicious = {
        "185.220.101.5": {"abuseConfidenceScore": 98, "countryCode": "DE", "usageType": "Tor Exit Node", "domain": "tor-exit.de"},
        "103.253.145.22": {"abuseConfidenceScore": 87, "countryCode": "CN", "usageType": "Data Center/Web Hosting", "domain": "host-provider.net"},
        "45.154.255.88": {"abuseConfidenceScore": 92, "countryCode": "RU", "usageType": "VPN/Proxy", "domain": "vpn-node.ru"}
    }
    
    if ip in known_malicious:
        data = known_malicious[ip]
    else:
        # Default benign info
        data = {"abuseConfidenceScore": 0, "countryCode": "US", "usageType": "ISP / Residential", "domain": "clean-host.net"}
        
    return {
        "ip": ip,
        "abuse_score": data["abuseConfidenceScore"],
        "country": data["countryCode"],
        "usage_type": data["usageType"],
        "domain": data["domain"],
        "last_checked": time.time()
    }

# Mount static React dashboard dist if available
DIST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "dist")
if os.path.exists(DIST_PATH):
    app.mount("/", StaticFiles(directory=DIST_PATH, html=True), name="static")
else:
    @app.get("/")
    def root_fallback():
        return {
            "message": "Personal IDS/IPS API Server Running!",
            "docs": "/docs",
            "dashboard_status": "Front-end dist folder not found yet. Build react app or visit /docs for API."
        }
