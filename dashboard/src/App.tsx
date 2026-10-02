import React, { useState, useEffect } from 'react';
import { StatsData, AlertItem, PacketLog, RuleItem, BlockedIP } from './types';
import {
  fetchStats,
  fetchAlerts,
  fetchPackets,
  fetchRules,
  fetchBlockedIPs
} from './api';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { LogsPage } from './pages/LogsPage';
import { RulesPage } from './pages/RulesPage';
import { BlockedPage } from './pages/BlockedPage';
import { ThreatModal } from './components/ThreatModal';
import { Language, translations } from './i18n';

export const App: React.FC = () => {
  const [lang, setLangState] = useState<Language>(() => {
    const saved = localStorage.getItem('aegis_lang');
    return (saved === 'en' || saved === 'vi') ? saved : 'vi';
  });

  const setLang = (newLang: Language) => {
    setLangState(newLang);
    localStorage.setItem('aegis_lang', newLang);
  };

  const t = translations[lang];

  const [activeTab, setActiveTab] = useState<'dashboard' | 'logs' | 'rules' | 'blocked'>('dashboard');
  const [stats, setStats] = useState<StatsData | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [packets, setPackets] = useState<PacketLog[]>([]);
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIP[]>([]);
  
  const [inspectIp, setInspectIp] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [sData, aData, pData, rData, bData] = await Promise.all([
        fetchStats(),
        fetchAlerts(100),
        fetchPackets(100),
        fetchRules(),
        fetchBlockedIPs()
      ]);
      setStats(sData);
      setAlerts(aData);
      setPackets(pData);
      setRules(rData);
      setBlockedIps(bData);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 2000); // 2-second real-time polling
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0b0f19] text-gray-100 flex flex-col font-sans">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        capturerMode={stats?.capturer_mode || 'Starting'}
        activeRulesCount={stats?.active_rules_count || 0}
        lang={lang}
        setLang={setLang}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 pb-12">
        {activeTab === 'dashboard' && (
          <DashboardPage
            stats={stats}
            alerts={alerts}
            onSelectIp={(ip) => setInspectIp(ip)}
            lang={lang}
          />
        )}

        {activeTab === 'logs' && (
          <LogsPage
            alerts={alerts}
            packets={packets}
            onSelectIp={(ip) => setInspectIp(ip)}
            lang={lang}
          />
        )}

        {activeTab === 'rules' && (
          <RulesPage
            rules={rules}
            onRefreshRules={loadData}
            lang={lang}
          />
        )}

        {activeTab === 'blocked' && (
          <BlockedPage
            blockedIps={blockedIps}
            onRefresh={loadData}
            onSelectIp={(ip) => setInspectIp(ip)}
            lang={lang}
          />
        )}
      </main>

      {/* Threat Intel Inspection Modal */}
      <ThreatModal
        ip={inspectIp}
        onClose={() => setInspectIp(null)}
        onBlockToggled={loadData}
        isBlockedInitially={blockedIps.some(b => b.ip === inspectIp)}
        lang={lang}
      />

      <footer className="border-t border-gray-800/80 py-4 text-center text-xs text-gray-500 font-mono">
        {t.footer}
      </footer>
    </div>
  );
};

export default App;
