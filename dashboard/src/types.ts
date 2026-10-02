export interface StatsData {
  total_packets: number;
  total_alerts: number;
  alerts_24h: number;
  blocked_ips_count: number;
  capturer_mode: string;
  active_rules_count: number;
  total_rules_count: number;
  severity_distribution: Record<string, number>;
  protocol_distribution: Array<{ protocol: string; count: number }>;
  top_suspicious_sources: Array<{ ip: string; count: number }>;
}

export interface AlertItem {
  id: number;
  timestamp: number;
  rule_id: string;
  rule_name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  mitre_attack: string;
  description: string;
}

export interface PacketLog {
  id: number;
  timestamp: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  length: number;
  info: string;
}

export interface RuleItem {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  enabled: boolean;
  condition: Record<string, any>;
  action: Record<string, any>;
  mitre_attack?: string;
  tags?: string[];
}

export interface BlockedIP {
  ip: string;
  reason: string;
  blocked_at: number;
}

export interface ThreatIntelData {
  ip: string;
  abuse_score: number;
  country: string;
  usage_type: string;
  domain: string;
  last_checked: number;
}
