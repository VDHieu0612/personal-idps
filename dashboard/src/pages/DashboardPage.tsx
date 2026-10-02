import React from 'react';
import { StatsData, AlertItem } from '../types';
import { StatCard } from '../components/StatCard';
import { Activity, ShieldAlert, Radio, AlertOctagon, ExternalLink, ShieldCheck } from 'lucide-react';
import { Language, translations } from '../i18n';

interface DashboardPageProps {
  stats: StatsData | null;
  alerts: AlertItem[];
  onSelectIp: (ip: string) => void;
  lang: Language;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  alerts,
  onSelectIp,
  lang
}) => {
  const t = translations[lang];

  const severityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Stat Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title={t.stats.totalPackets}
          value={stats ? stats.total_packets.toLocaleString() : '0'}
          subtitle={t.stats.totalPacketsSub}
          variant="blue"
          icon={<Activity className="w-5 h-5" />}
        />
        <StatCard
          title={t.stats.alerts24h}
          value={stats ? stats.alerts_24h : 0}
          subtitle={`${t.stats.alertsTotalSub}: ${stats ? stats.total_alerts : 0}`}
          variant="red"
          icon={<AlertOctagon className="w-5 h-5" />}
        />
        <StatCard
          title={t.stats.activeRules}
          value={stats ? `${stats.active_rules_count} / ${stats.total_rules_count}` : '0'}
          subtitle={t.stats.activeRulesSub}
          variant="amber"
          icon={<Radio className="w-5 h-5" />}
        />
        <StatCard
          title={t.stats.blockedIps}
          value={stats ? stats.blocked_ips_count : 0}
          subtitle={t.stats.blockedIpsSub}
          variant="emerald"
          icon={<ShieldCheck className="w-5 h-5" />}
        />
      </div>

      {/* Main Charts & Analytics Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="glass-panel p-5 rounded-2xl border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">{t.dashboard.severityDist}</h3>
            <span className="text-xs text-gray-400 font-mono">{t.dashboard.liveSync}</span>
          </div>

          <div className="space-y-3 pt-2">
            {['critical', 'high', 'medium', 'low'].map((sev) => {
              const count = stats?.severity_distribution?.[sev] || 0;
              const total = stats?.total_alerts || 1;
              const pct = Math.round((count / total) * 100);

              const barColors: Record<string, string> = {
                critical: 'bg-red-500',
                high: 'bg-orange-500',
                medium: 'bg-amber-500',
                low: 'bg-blue-500',
              };

              return (
                <div key={sev} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="capitalize text-gray-300 font-semibold">{sev}</span>
                    <span className="text-gray-400">{count} ({pct}%)</span>
                  </div>
                  <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${barColors[sev]} transition-all duration-500`}
                      style={{ width: `${Math.max(pct, 4)}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Suspicious Source IPs */}
        <div className="glass-panel p-5 rounded-2xl border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">{t.dashboard.topSources}</h3>
            <span className="text-xs text-gray-400 font-mono">{t.dashboard.abuseCounter}</span>
          </div>

          <div className="space-y-2.5 pt-1">
            {stats?.top_suspicious_sources && stats.top_suspicious_sources.length > 0 ? (
              stats.top_suspicious_sources.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => onSelectIp(item.ip)}
                  className="flex items-center justify-between p-2.5 rounded-xl bg-gray-900/60 border border-gray-800/80 hover:border-blue-500/40 hover:bg-gray-800/60 cursor-pointer transition"
                >
                  <div className="flex items-center space-x-2.5">
                    <span className="text-xs font-mono text-gray-500 font-bold">#{idx + 1}</span>
                    <span className="font-mono text-sm text-blue-400 font-medium hover:underline flex items-center gap-1">
                      {item.ip}
                      <ExternalLink className="w-3 h-3 text-gray-500" />
                    </span>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20 font-semibold">
                    {item.count} {t.dashboard.alertsCount}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-xs text-gray-500 py-6 text-center">{t.dashboard.noThreatSources}</p>
            )}
          </div>
        </div>

        {/* Protocol Breakdowns */}
        <div className="glass-panel p-5 rounded-2xl border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">{t.dashboard.protocols}</h3>
            <span className="text-xs text-gray-400 font-mono">{t.dashboard.networkLayer}</span>
          </div>

          <div className="space-y-3 pt-2">
            {stats?.protocol_distribution && stats.protocol_distribution.length > 0 ? (
              stats.protocol_distribution.map((item) => (
                <div key={item.protocol} className="flex items-center justify-between p-2.5 rounded-xl bg-gray-900/40 border border-gray-800">
                  <div className="flex items-center space-x-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-blue-400"></div>
                    <span className="font-mono text-xs font-semibold text-gray-200">{item.protocol}</span>
                  </div>
                  <span className="font-mono text-xs text-gray-400 font-bold">{item.count.toLocaleString()} {t.dashboard.pktsCount}</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-gray-500 py-6 text-center">{t.dashboard.listeningProtocols}</p>
            )}
          </div>
        </div>
      </div>

      {/* Live Recent Alerts Feed Table */}
      <div className="glass-panel rounded-2xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/40">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h3 className="font-semibold text-white text-base">{t.dashboard.recentAlerts}</h3>
          </div>
          <span className="text-xs text-gray-400 font-mono">{t.dashboard.autoRefresh}</span>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/80 text-gray-400 uppercase text-[11px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="px-6 py-3">{t.table.time}</th>
                <th className="px-6 py-3">{t.table.severity}</th>
                <th className="px-6 py-3">{t.table.ruleName}</th>
                <th className="px-6 py-3">{t.table.srcIp}</th>
                <th className="px-6 py-3">{t.table.dstIp}</th>
                <th className="px-6 py-3">{t.table.mitre}</th>
                <th className="px-6 py-3">{t.table.details}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {alerts.length > 0 ? (
                alerts.slice(0, 10).map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-800/40 transition-colors">
                    <td className="px-6 py-3.5 text-gray-400 whitespace-nowrap">
                      {new Date(alert.timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-3.5 whitespace-nowrap">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border uppercase ${severityColors[alert.severity] || severityColors.medium}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 font-semibold text-white whitespace-nowrap">
                      {alert.rule_name}
                    </td>
                    <td className="px-6 py-3.5 text-blue-400 font-medium whitespace-nowrap hover:underline cursor-pointer" onClick={() => onSelectIp(alert.src_ip)}>
                      {alert.src_ip}:{alert.src_port}
                    </td>
                    <td className="px-6 py-3.5 text-gray-300 whitespace-nowrap">
                      {alert.dst_ip}:{alert.dst_port}
                    </td>
                    <td className="px-6 py-3.5 text-purple-400 whitespace-nowrap font-bold">
                      {alert.mitre_attack || 'N/A'}
                    </td>
                    <td className="px-6 py-3.5 text-gray-400 max-w-xs truncate">
                      {alert.description}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-gray-500">
                    {t.dashboard.noAlerts}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
