import os
import sys
import glob
import yaml
import time

if sys.platform.startswith('win'):
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from collections import defaultdict, deque
from typing import Dict, List, Any
from .db import create_alert, get_db

class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules: List[Dict[str, Any]] = []
        
        # State tracking for sliding window detection
        # src_ip -> deque of (timestamp, dst_port)
        self.ip_port_history = defaultdict(deque)
        
        # (src_ip, target_port) -> deque of timestamp
        self.ip_target_history = defaultdict(deque)
        
        # (src_ip, protocol) -> deque of timestamp
        self.ip_proto_history = defaultdict(deque)
        
        # Cooldown dictionary to avoid spamming identical alerts: (rule_id, src_ip) -> timestamp
        self.alert_cooldown = {}
        self.cooldown_period = 10  # seconds

        self.load_rules()

    def load_rules(self):
        self.rules = []
        pattern = os.path.join(self.rules_dir, "*.yml")
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data:
                        rule_data["filepath"] = filepath
                        self.rules.append(rule_data)
            except Exception as e:
                print(f"[RuleEngine Error] Failed loading {filepath}: {e}")
        print(f"[RuleEngine] Loaded {len(self.rules)} rules from {self.rules_dir}")

    def save_rule(self, rule_data: Dict[str, Any]) -> str:
        rule_id = rule_data.get("id")
        filename = f"{rule_id}.yml" if not rule_id.startswith("rule-") else f"{rule_id}.yml"
        filepath = os.path.join(self.rules_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(rule_data, f, sort_keys=False)
            
        self.load_rules()
        return filepath

    def toggle_rule(self, rule_id: str, enabled: bool):
        for r in self.rules:
            if r.get("id") == rule_id:
                r["enabled"] = enabled
                if "filepath" in r:
                    with open(r["filepath"], "w", encoding="utf-8") as f:
                        save_data = {k: v for k, v in r.items() if k != "filepath"}
                        yaml.dump(save_data, f, sort_keys=False)
                break

    def bulk_toggle_rules(self, rule_ids: List[str] = None, category: str = None, enabled: bool = True):
        for r in self.rules:
            should_toggle = False
            if rule_ids and r.get("id") in rule_ids:
                should_toggle = True
            elif category and r.get("category") == category:
                should_toggle = True
            elif not rule_ids and not category:
                should_toggle = True

            if should_toggle:
                r["enabled"] = enabled
                if "filepath" in r:
                    with open(r["filepath"], "w", encoding="utf-8") as f:
                        save_data = {k: v for k, v in r.items() if k != "filepath"}
                        yaml.dump(save_data, f, sort_keys=False)

    def process_packet(self, packet_info: Dict[str, Any]):
        now = time.time()
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "RAW")
        length = packet_info.get("length", 0)
        info = packet_info.get("info", "")

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            rule_id = rule.get("id")
            rule_name = rule.get("name")
            severity = rule.get("severity", "medium")
            category = rule.get("category", "general")
            mitre = rule.get("mitre_attack", "")
            condition = rule.get("condition", {})
            cond_type = condition.get("type")

            triggered = False
            desc = ""

            # Check cooldown
            cooldown_key = (rule_id, src_ip)
            if cooldown_key in self.alert_cooldown:
                if now - self.alert_cooldown[cooldown_key] < self.cooldown_period:
                    continue

            # Rule Type 1: Threshold (e.g. Port Scan)
            if cond_type == "threshold":
                window = condition.get("window_seconds", 10)
                limit = condition.get("threshold_count", 15)
                
                history = self.ip_port_history[src_ip]
                history.append((now, dst_port))
                
                # Cleanup old entries
                while history and now - history[0][0] > window:
                    history.popleft()
                    
                unique_ports = {item[1] for item in history}
                if len(unique_ports) >= limit:
                    triggered = True
                    desc = f"Scanned {len(unique_ports)} distinct ports in {window}s"

            # Rule Type 2: Single Target Rate (e.g. SSH/RDP Brute force)
            elif cond_type == "single_target_rate":
                target_port = condition.get("target_port")
                if dst_port == target_port:
                    window = condition.get("window_seconds", 5)
                    limit = condition.get("threshold_count", 5)
                    
                    key = (src_ip, target_port)
                    history = self.ip_target_history[key]
                    history.append(now)
                    
                    while history and now - history[0] > window:
                        history.popleft()
                        
                    if len(history) >= limit:
                        triggered = True
                        desc = f"{len(history)} connection attempts to port {target_port} in {window}s"

            # Rule Type 3: Protocol Rate (e.g. ICMP Flood)
            elif cond_type == "protocol_rate":
                target_proto = condition.get("protocol")
                if protocol.upper() == target_proto.upper():
                    window = condition.get("window_seconds", 5)
                    limit = condition.get("threshold_count", 50)
                    
                    key = (src_ip, target_proto)
                    history = self.ip_proto_history[key]
                    history.append(now)
                    
                    while history and now - history[0] > window:
                        history.popleft()
                        
                    if len(history) >= limit:
                        triggered = True
                        desc = f"High volume {target_proto} rate ({len(history)} pkts/{window}s)"

            # Rule Type 4: Port Match (e.g. Tor/C2 ports)
            elif cond_type == "port_match":
                ports = condition.get("ports", [])
                if dst_port in ports or src_port in ports:
                    triggered = True
                    match_port = dst_port if dst_port in ports else src_port
                    desc = f"Traffic matching monitored suspicious port {match_port}"

            # Rule Type 5: Packet Size (e.g. Large Payload)
            elif cond_type == "packet_size":
                max_bytes = condition.get("max_bytes", 8192)
                if length >= max_bytes:
                    triggered = True
                    desc = f"Packet length {length} bytes exceeds threshold {max_bytes} bytes"

            # Rule Type 6: DNS Anomaly
            elif cond_type == "dns_length":
                if protocol == "DNS":
                    max_len = condition.get("max_query_length", 60)
                    if len(info) >= max_len:
                        triggered = True
                        desc = f"Abnormally long DNS query domain string ({len(info)} chars): {info[:40]}..."

            if triggered:
                self.alert_cooldown[cooldown_key] = now
                create_alert(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    category=category,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    mitre_attack=mitre,
                    description=desc
                )
