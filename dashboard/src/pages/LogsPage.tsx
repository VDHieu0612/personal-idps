import React, { useState } from 'react';
import { AlertItem, PacketLog } from '../types';
import { Search, Filter, ShieldAlert, Radio } from 'lucide-react';
import { Language, translations } from '../i18n';

interface LogsPageProps {
  alerts: AlertItem[];
  packets: PacketLog[];
  onSelectIp: (ip: string) => void;
  lang: Language;
}

export const LogsPage: React.FC<LogsPageProps> = ({
  alerts,
  packets,
  onSelectIp,
  lang
}) => {
  const t = translations[lang];

  const [subTab, setSubTab] = useState<'alerts' | 'packets'>('alerts');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const filteredAlerts = alerts.filter(a => {
    const matchSearch =
      a.src_ip.includes(search) ||
      a.dst_ip.includes(search) ||
      a.rule_name.toLowerCase().includes(search.toLowerCase()) ||
      a.description.toLowerCase().includes(search.toLowerCase());

    const matchSev = severityFilter === 'all' || a.severity === severityFilter;
    return matchSearch && matchSev;
  });

  const filteredPackets = packets.filter(p => {
    return (
      p.src_ip.includes(search) ||
      p.dst_ip.includes(search) ||
      p.protocol.toLowerCase().includes(search.toLowerCase()) ||
      p.info.toLowerCase().includes(search.toLowerCase())
    );
  });

  const severityBadges: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Sub-tab selection & search bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-4 rounded-2xl border border-gray-800">
        <div className="flex items-center space-x-2 bg-gray-950/80 p-1 rounded-xl border border-gray-800">
          <button
            onClick={() => setSubTab('alerts')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              subTab === 'alerts' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-400 hover:text-white'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{t.logs.subTabAlerts} ({filteredAlerts.length})</span>
          </button>
          <button
            onClick={() => setSubTab('packets')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              subTab === 'packets' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Radio className="w-4 h-4" />
            <span>{t.logs.subTabPackets} ({filteredPackets.length})</span>
          </button>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-3">
          {subTab === 'alerts' && (
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-gray-900 border border-gray-800 text-xs text-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500"
              >
                <option value="all">{t.logs.allSeverities}</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          )}

          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder={t.logs.searchPlaceholder}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-gray-900 border border-gray-800 text-xs text-gray-200 pl-9 pr-4 py-2 rounded-xl focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Table Display */}
      <div className="glass-panel rounded-2xl border border-gray-800 overflow-hidden">
        {subTab === 'alerts' ? (
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-gray-900/80 text-gray-400 uppercase text-[11px] tracking-wider border-b border-gray-800">
                <tr>
                  <th className="px-6 py-3.5">{t.table.timestamp}</th>
                  <th className="px-6 py-3.5">{t.table.severity}</th>
                  <th className="px-6 py-3.5">{t.table.ruleIdName}</th>
                  <th className="px-6 py-3.5">{t.table.srcIp}</th>
                  <th className="px-6 py-3.5">{t.table.dstIp}</th>
                  <th className="px-6 py-3.5">{t.table.protocol}</th>
                  <th className="px-6 py-3.5">{t.table.mitre}</th>
                  <th className="px-6 py-3.5">{t.table.details}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {filteredAlerts.length > 0 ? (
                  filteredAlerts.map(alert => (
                    <tr key={alert.id} className="hover:bg-gray-800/40 transition">
                      <td className="px-6 py-3.5 text-gray-400 whitespace-nowrap">
                        {new Date(alert.timestamp * 1000).toLocaleString()}
                      </td>
                      <td className="px-6 py-3.5 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border uppercase ${severityBadges[alert.severity]}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="px-6 py-3.5 font-semibold text-white whitespace-nowrap">
                        <span className="text-gray-500 mr-2 text-[10px]">{alert.rule_id}</span>
                        {alert.rule_name}
                      </td>
                      <td
                        className="px-6 py-3.5 text-blue-400 font-medium whitespace-nowrap cursor-pointer hover:underline"
                        onClick={() => onSelectIp(alert.src_ip)}
                      >
                        {alert.src_ip}:{alert.src_port}
                      </td>
                      <td className="px-6 py-3.5 text-gray-300 whitespace-nowrap">
                        {alert.dst_ip}:{alert.dst_port}
                      </td>
                      <td className="px-6 py-3.5 text-emerald-400 font-bold whitespace-nowrap">
                        {alert.protocol}
                      </td>
                      <td className="px-6 py-3.5 text-purple-400 font-bold whitespace-nowrap">
                        {alert.mitre_attack || '-'}
                      </td>
                      <td className="px-6 py-3.5 text-gray-400 max-w-sm truncate">
                        {alert.description}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="px-6 py-12 text-center text-gray-500">
                      {t.logs.noAlertsMatch}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-gray-900/80 text-gray-400 uppercase text-[11px] tracking-wider border-b border-gray-800">
                <tr>
                  <th className="px-6 py-3.5">{t.table.time}</th>
                  <th className="px-6 py-3.5">{t.table.srcIpPort}</th>
                  <th className="px-6 py-3.5">{t.table.dstIpPort}</th>
                  <th className="px-6 py-3.5">{t.table.protocol}</th>
                  <th className="px-6 py-3.5">{t.table.length}</th>
                  <th className="px-6 py-3.5">{t.table.info}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {filteredPackets.length > 0 ? (
                  filteredPackets.map(pkt => (
                    <tr key={pkt.id} className="hover:bg-gray-800/40 transition">
                      <td className="px-6 py-3.5 text-gray-400 whitespace-nowrap">
                        {new Date(pkt.timestamp * 1000).toLocaleTimeString()}
                      </td>
                      <td
                        className="px-6 py-3.5 text-blue-400 whitespace-nowrap cursor-pointer hover:underline"
                        onClick={() => onSelectIp(pkt.src_ip)}
                      >
                        {pkt.src_ip}:{pkt.src_port}
                      </td>
                      <td className="px-6 py-3.5 text-gray-300 whitespace-nowrap">
                        {pkt.dst_ip}:{pkt.dst_port}
                      </td>
                      <td className="px-6 py-3.5 text-indigo-400 font-semibold whitespace-nowrap">
                        {pkt.protocol}
                      </td>
                      <td className="px-6 py-3.5 text-gray-400 whitespace-nowrap">
                        {pkt.length} B
                      </td>
                      <td className="px-6 py-3.5 text-gray-400 max-w-md truncate">
                        {pkt.info || 'Payload data packet'}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                      {t.logs.noPacketsMatch}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
