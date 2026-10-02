import React from 'react';
import { Shield, Activity, ListFilter, SlidersHorizontal, ShieldAlert, Cpu, Languages } from 'lucide-react';
import { Language, translations } from '../i18n';

interface NavbarProps {
  activeTab: 'dashboard' | 'logs' | 'rules' | 'blocked';
  setActiveTab: (tab: 'dashboard' | 'logs' | 'rules' | 'blocked') => void;
  capturerMode?: string;
  activeRulesCount?: number;
  lang: Language;
  setLang: (lang: Language) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  capturerMode = 'Live',
  activeRulesCount = 0,
  lang,
  setLang
}) => {
  const t = translations[lang];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-gray-800/80 px-4 lg:px-8 py-3.5 mb-6">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Logo & Brand Title */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/30 shadow-lg shadow-blue-500/10">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-300 to-purple-400">
                AEGISGUARD
              </h1>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {t.versionBadge}
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono">{t.brandSubtitle}</p>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex items-center space-x-1 bg-gray-900/80 p-1.5 rounded-xl border border-gray-800">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === 'dashboard'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>{t.tabs.dashboard}</span>
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === 'logs'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <ListFilter className="w-4 h-4" />
            <span>{t.tabs.logs}</span>
          </button>

          <button
            onClick={() => setActiveTab('rules')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === 'rules'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <SlidersHorizontal className="w-4 h-4" />
            <span>{t.tabs.rules} ({activeRulesCount})</span>
          </button>

          <button
            onClick={() => setActiveTab('blocked')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === 'blocked'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{t.tabs.blocked}</span>
          </button>
        </nav>

        {/* System Engine Status & Language Switcher */}
        <div className="flex items-center space-x-2.5 text-xs">
          {/* Language Switcher Button */}
          <button
            onClick={() => setLang(lang === 'en' ? 'vi' : 'en')}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-700/80 hover:border-blue-500/50 text-gray-200 hover:text-white transition shadow-sm"
            title={lang === 'en' ? "Chuyển sang Tiếng Việt" : "Switch to English"}
          >
            <Languages className="w-3.5 h-3.5 text-blue-400" />
            <span className="font-semibold text-[11px] font-mono">
              {lang === 'en' ? '🇻🇳 VI' : '🇬🇧 EN'}
            </span>
          </button>

          <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800">
            <Cpu className="w-4 h-4 text-emerald-400" />
            <span className="text-gray-400">{t.status.mode}:</span>
            <span className="font-semibold text-emerald-400 truncate max-w-[140px]">{capturerMode}</span>
          </div>
          <div className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span>{t.status.active}</span>
          </div>
        </div>
      </div>
    </header>
  );
};
