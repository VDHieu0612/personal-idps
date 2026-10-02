import React, { useState } from 'react';
import { BlockedIP } from '../types';
import { toggleBlockIP } from '../api';
import { ShieldAlert, ShieldCheck, Plus } from 'lucide-react';
import { Language, translations } from '../i18n';

interface BlockedPageProps {
  blockedIps: BlockedIP[];
  onRefresh: () => void;
  onSelectIp: (ip: string) => void;
  lang: Language;
}

export const BlockedPage: React.FC<BlockedPageProps> = ({
  blockedIps,
  onRefresh,
  onSelectIp,
  lang
}) => {
  const t = translations[lang];

  const [newIp, setNewIp] = useState('');
  const [reason, setReason] = useState(t.blocked.defaultReason);
  const [loading, setLoading] = useState(false);

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;

    setLoading(true);
    try {
      await toggleBlockIP(newIp.trim(), reason || t.blocked.defaultReason);
      setNewIp('');
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      await toggleBlockIP(ip);
      onRefresh();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Manual Block Card */}
      <div className="glass-panel p-5 rounded-2xl border border-gray-800 space-y-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <span>{t.blocked.title}</span>
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            {t.blocked.subtitle}
          </p>
        </div>

        <form onSubmit={handleManualBlock} className="flex flex-col sm:flex-row gap-3 pt-2">
          <input
            type="text"
            placeholder={t.blocked.ipPlaceholder}
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            className="flex-1 bg-gray-900 border border-gray-800 text-xs text-white px-4 py-2.5 rounded-xl focus:outline-none focus:border-red-500 font-mono"
          />
          <input
            type="text"
            placeholder={t.blocked.reasonPlaceholder}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="flex-1 bg-gray-900 border border-gray-800 text-xs text-white px-4 py-2.5 rounded-xl focus:outline-none focus:border-red-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-red-600 hover:bg-red-500 text-white text-xs font-semibold px-5 py-2.5 rounded-xl shadow-lg shadow-red-600/20 transition flex items-center justify-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>{t.blocked.btnBlock}</span>
          </button>
        </form>
      </div>

      {/* Blocked IP Table */}
      <div className="glass-panel rounded-2xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/40">
          <h3 className="font-semibold text-white text-sm">{t.blocked.tableTitle} ({blockedIps.length})</h3>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/80 text-gray-400 uppercase text-[11px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="px-6 py-3.5">{t.table.srcIp}</th>
                <th className="px-6 py-3.5">{t.blocked.reasonHeader}</th>
                <th className="px-6 py-3.5">{t.blocked.blockedAtHeader}</th>
                <th className="px-6 py-3.5 text-right">{t.table.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {blockedIps.length > 0 ? (
                blockedIps.map((item) => (
                  <tr key={item.ip} className="hover:bg-gray-800/40 transition">
                    <td
                      className="px-6 py-3.5 text-blue-400 font-semibold cursor-pointer hover:underline"
                      onClick={() => onSelectIp(item.ip)}
                    >
                      {item.ip}
                    </td>
                    <td className="px-6 py-3.5 text-gray-300">
                      {item.reason}
                    </td>
                    <td className="px-6 py-3.5 text-gray-400">
                      {new Date(item.blocked_at * 1000).toLocaleString()}
                    </td>
                    <td className="px-6 py-3.5 text-right">
                      <button
                        onClick={() => handleUnblock(item.ip)}
                        className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition text-xs font-medium inline-flex items-center space-x-1"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>{t.blocked.btnUnblock}</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-gray-500">
                    {t.blocked.noBlocked}
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
