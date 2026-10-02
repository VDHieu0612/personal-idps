import { StatsData, AlertItem, PacketLog, RuleItem, BlockedIP, ThreatIntelData } from './types';

const API_BASE = '/api';

export async function fetchStats(): Promise<StatsData> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchAlerts(limit = 50): Promise<AlertItem[]> {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchPackets(limit = 50): Promise<PacketLog[]> {
  const res = await fetch(`${API_BASE}/packets?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch packets');
  return res.json();
}

export async function fetchRules(): Promise<RuleItem[]> {
  const res = await fetch(`${API_BASE}/rules`);
  if (!res.ok) throw new Error('Failed to fetch rules');
  return res.json();
}

export async function toggleRule(ruleId: string, enabled: boolean): Promise<any> {
  const res = await fetch(`${API_BASE}/rules/toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule_id: ruleId, enabled }),
  });
  if (!res.ok) throw new Error('Failed to toggle rule');
  return res.json();
}

export async function bulkToggleRules(ruleIds?: string[], category?: string, enabled = true): Promise<any> {
  const res = await fetch(`${API_BASE}/rules/bulk-toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule_ids: ruleIds, category, enabled }),
  });
  if (!res.ok) throw new Error('Failed bulk toggle');
  return res.json();
}

export async function saveRule(rule: Partial<RuleItem>): Promise<any> {
  const res = await fetch(`${API_BASE}/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rule),
  });
  if (!res.ok) throw new Error('Failed to save rule');
  return res.json();
}

export async function fetchETCategories(): Promise<Array<{ id: string; name: string; desc: string }>> {
  const res = await fetch(`${API_BASE}/rules/et-categories`);
  if (!res.ok) throw new Error('Failed to fetch ET categories');
  return res.json();
}

export async function fetchAndImportETCategory(categoryFile: string, maxRules = 50): Promise<any> {
  const res = await fetch(`${API_BASE}/rules/fetch-et-category`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ category_file: categoryFile, max_rules: maxRules }),
  });
  if (!res.ok) throw new Error('Failed to fetch and import ET category');
  return res.json();
}

export async function fetchSuricataSample(): Promise<string> {
  const res = await fetch(`${API_BASE}/rules/suricata-sample`);
  if (!res.ok) throw new Error('Failed to fetch Suricata sample');
  const data = await res.json();
  return data.content || '';
}

export async function importSuricataRules(content?: string, useSample = false): Promise<any> {
  const res = await fetch(`${API_BASE}/rules/import-suricata`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, use_sample: useSample }),
  });
  if (!res.ok) throw new Error('Failed to import Suricata rules');
  return res.json();
}

export async function fetchBlockedIPs(): Promise<BlockedIP[]> {
  const res = await fetch(`${API_BASE}/blocked-ips`);
  if (!res.ok) throw new Error('Failed to fetch blocked IPs');
  return res.json();
}

export async function toggleBlockIP(ip: string, reason = 'Manual Admin Action'): Promise<any> {
  const res = await fetch(`${API_BASE}/blocked-ips/toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });
  if (!res.ok) throw new Error('Failed to toggle block IP');
  return res.json();
}

export async function lookupThreatIntel(ip: string): Promise<ThreatIntelData> {
  const res = await fetch(`${API_BASE}/threat-intel/lookup?ip=${encodeURIComponent(ip)}`);
  if (!res.ok) throw new Error('Failed threat intel lookup');
  return res.json();
}
