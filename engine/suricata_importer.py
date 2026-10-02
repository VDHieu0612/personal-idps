import os
import re
import yaml
import requests
from typing import List, Dict, Any, Tuple

# Official Emerging Threats Open repository categories
ET_CATEGORIES = [
    {"id": "emerging-scan.rules", "name": "Reconnaissance & Vulnerability Scanners", "desc": "Port scanners, Nmap, Masscan, vulnerability probes (770+ rules)"},
    {"id": "emerging-dos.rules", "name": "Denial of Service (DoS & Floods)", "desc": "SYN flood, ICMP flood, Slowloris, UDP storms (260+ rules)"},
    {"id": "emerging-exploit.rules", "name": "Known CVE Exploits & RCE", "desc": "Active vulnerability exploits targeting services (4,200+ rules)"},
    {"id": "emerging-web_server.rules", "name": "Web Server & Web Shell Attacks", "desc": "Apache, Nginx, IIS probes, SQLi, RFI, webshells"},
    {"id": "emerging-worm.rules", "name": "Worms & Fast Network Propagation", "desc": "Self-replicating malware network propagation"},
    {"id": "emerging-ftp.rules", "name": "FTP Insecure Protocols & Exploits", "desc": "FTP brute force, path traversal, exploit payloads (270+ rules)"},
    {"id": "emerging-telnet.rules", "name": "Telnet Cleartext & Scanners", "desc": "Telnet scanners, brute force, insecure authentication (60+ rules)"},
    {"id": "emerging-attack_response.rules", "name": "Attack Responses & Exfiltration", "desc": "Shell prompt replies, leaked credentials, exfiltration traces"},
]

# Sample starter rules snippet
SAMPLE_ET_RULES = """
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 30; classtype:attempted-recon; sid:2001219; rev:20;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET SCAN Potential RDP Scan / Brute Force"; flags:S; threshold:type both, track by_src, count 5, seconds 15; classtype:attempted-recon; sid:2008543; rev:5;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET SCAN Potential FTP Brute Force Probe"; flags:S; threshold:type both, track by_src, count 5, seconds 20; classtype:attempted-recon; sid:2002381; rev:8;)
alert tcp $EXTERNAL_NET any -> $HOME_NET [80,8080,8888] (msg:"ET WEB_SPECIFIC_APPS Potential Web Shell Execution Probe"; flow:established,to_server; classtype:web-application-attack; sid:2018933; rev:3;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555] (msg:"ET TROJAN Metasploit Default Handler Outbound Callback"; flow:established,to_server; classtype:trojan-activity; sid:2003328; rev:6;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [50050,50051] (msg:"ET TROJAN Cobalt Strike Beacon Default Port Communication"; flow:established,to_server; classtype:trojan-activity; sid:2028882; rev:4;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"ET SCAN Inbound Telnet Scanner Probe"; flags:S; threshold:type both, track by_src, count 4, seconds 10; classtype:attempted-recon; sid:2001220; rev:11;)
alert tcp $EXTERNAL_NET any -> $HOME_NET [3306,5432] (msg:"ET POLICY Database Service External Exposure Connection"; classtype:policy-violation; sid:2010992; rev:2;)
alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET SCAN External DNS Amplification / High Volume Flood"; threshold:type both, track by_src, count 30, seconds 5; classtype:denial-of-service; sid:2014755; rev:4;)
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Potential ICMP Ping Flooding"; threshold:type both, track by_src, count 50, seconds 5; itype:8; classtype:denial-of-service; sid:2000350; rev:7;)
"""

def fetch_et_open_category(category_file: str) -> str:
    url = f"https://rules.emergingthreats.net/open/suricata-5.0/rules/{category_file}"
    resp = requests.get(url, timeout=12)
    resp.raise_for_status()
    return resp.text

def parse_suricata_rule(rule_text: str) -> Dict[str, Any] | None:
    rule_text = rule_text.strip()
    if not rule_text or rule_text.startswith('#'):
        return None

    # Regex for standard Snort/Suricata header:
    # action proto src_ip src_port dir dst_ip dst_port (options)
    header_pattern = r'^(alert|log|pass|drop|reject)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+(->|<>)\s+([^\s]+)\s+([^\s]+)\s*\((.*)\);?\s*$'
    match = re.match(header_pattern, rule_text, re.IGNORECASE)
    if not match:
        return None

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_str = match.groups()

    # Extract options key-values
    options = {}
    for opt in re.findall(r'(\w+(?:\.\w+)?)(?::\s*([^;]+))?;', options_str):
        key = opt[0].strip()
        val = opt[1].strip() if opt[1] else True
        options[key] = val

    msg = options.get('msg', 'Imported Suricata Rule').strip('"')
    sid = options.get('sid', str(abs(hash(msg)) % 1000000))
    classtype = options.get('classtype', 'unknown').lower()

    # Map classtype to category
    category = "general"
    severity = "medium"

    if 'recon' in classtype or 'scan' in classtype:
        category = "reconnaissance"
        severity = "high"
    elif 'trojan' in classtype or 'malware' in classtype or 'botnet' in classtype:
        category = "command_and_control"
        severity = "critical"
    elif 'web' in classtype or 'exploit' in classtype or 'shell' in classtype:
        category = "web_security"
        severity = "critical"
    elif 'denial' in classtype or 'dos' in classtype:
        category = "denial_of_service"
        severity = "medium"
    elif 'policy' in classtype or 'bad-traffic' in classtype or 'telnet' in classtype:
        category = "credential_access"
        severity = "medium"

    # Map condition
    condition: Dict[str, Any] = {}
    
    # Check for threshold option (e.g. count 5, seconds 30)
    threshold_str = options.get('threshold', '')
    if threshold_str:
        count_match = re.search(r'count\s+(\d+)', threshold_str)
        seconds_match = re.search(r'seconds\s+(\d+)', threshold_str)
        count = int(count_match.group(1)) if count_match else 5
        seconds = int(seconds_match.group(1)) if seconds_match else 10

        cleaned_port = dst_port.replace('[', '').replace(']', '')
        if cleaned_port.isdigit():
            condition = {
                "type": "single_target_rate",
                "target_port": int(cleaned_port),
                "threshold_count": count,
                "window_seconds": seconds,
                "group_by": "src_ip"
            }
        else:
            condition = {
                "type": "threshold",
                "field": "dst_port",
                "threshold_count": count,
                "window_seconds": seconds,
                "group_by": "src_ip"
            }
    else:
        # Port match condition
        cleaned_ports = dst_port.replace('[', '').replace(']', '').split(',')
        ports = [int(p.strip()) for p in cleaned_ports if p.strip().isdigit()]
        if ports:
            condition = {
                "type": "port_match",
                "ports": ports
            }
        else:
            condition = {
                "type": "threshold",
                "field": "dst_port",
                "threshold_count": 10,
                "window_seconds": 10,
                "group_by": "src_ip"
            }

    # MITRE ATT&CK reference tag
    mitre_attack = "T1046"
    if category == "command_and_control":
        mitre_attack = "T1071"
    elif category == "credential_access":
        mitre_attack = "T1110"
    elif category == "web_security":
        mitre_attack = "T1505.003"
    elif category == "denial_of_service":
        mitre_attack = "T1498"

    rule_dict = {
        "id": f"suricata-{sid}",
        "name": msg,
        "description": f"Imported from Suricata/ET Open rule (SID: {sid}, Classtype: {classtype})",
        "severity": severity,
        "category": category,
        "enabled": True,
        "condition": condition,
        "action": {
            "alert": True,
            "block_ip": severity == "critical"
        },
        "mitre_attack": mitre_attack,
        "tags": ["suricata_imported", category, f"sid_{sid}"]
    }

    return rule_dict

def import_suricata_rules_text(rules_text: str, rules_dir: str, max_rules: int = 60) -> List[Dict[str, Any]]:
    imported = []
    lines = rules_text.strip().splitlines()
    for line in lines:
        if len(imported) >= max_rules:
            break
        parsed = parse_suricata_rule(line)
        if parsed:
            rule_id = parsed["id"]
            filepath = os.path.join(rules_dir, f"{rule_id}.yml")
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(parsed, f, sort_keys=False)
            imported.append(parsed)
    return imported
