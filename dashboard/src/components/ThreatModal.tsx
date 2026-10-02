import React, { useEffect, useState } from 'react';
import { X, ShieldAlert, Globe, Server, CheckCircle, AlertTriangle } from 'lucide-react';
import { ThreatIntelData } from '../types';
import { lookupThreatIntel, toggleBlockIP } from '../api';
import { Language, translations } from '../i18n';

interface ThreatModalProps {
  ip: string | null;
  onClose: () => void;
  onBlockToggled?: () => void;
  isBlockedInitially?: boolean;
  lang: Language;
}

export const ThreatModal: React.FC<ThreatModalProps> = ({
  ip,
  onClose,
  onBlockToggled,
  isBlockedInitially = false,
  lang
}) => {
  const t = translations[lang];

  const [data, setData] = useState<ThreatIntelData | null>(null);
  const [loading, setLoading] = useState(false);
  const [isBlocked, setIsBlocked] = useState(isBlockedInitially);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    if (!ip) return;
    setLoading(true);
    lookupThreatIntel(ip)
      .then(res => setData(res))
      .catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, [ip]);

  if (!ip) return null;

  const handleToggleBlock = async () => {
    setActionLoading(true);
    try {
      const res = await toggleBlockIP(ip, t.threatModal.blockedReason);
      setIsBlocked(res.is_blocked);
      if (onBlockToggled) onBlockToggled();
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden glass-panel">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-900/60">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-lg text-white">{t.threatModal.title}</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5">
          <div className="flex items-center justify-between p-4 rounded-xl bg-gray-950/80 border border-gray-800">
            <div>
              <p className="text-xs text-gray-400 font-mono uppercase">{t.threatModal.targetIp}</p>
              <p className="text-xl font-bold font-mono text-blue-400">{ip}</p>
            </div>
            {isBlocked ? (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                {t.threatModal.statusBlocked}
              </span>
            ) : (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                {t.threatModal.statusAllowed}
              </span>
            )}
          </div>

          {loading ? (
            <div className="py-8 text-center text-gray-400 animate-pulse">
              {t.threatModal.querying}
            </div>
          ) : data ? (
            <div className="space-y-4 text-sm">
              {/* Score bar */}
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-medium text-gray-400">{t.threatModal.abuseScore}</span>
                  <span className={`font-mono font-bold text-sm ${data.abuse_score > 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {data.abuse_score}%
                  </span>
                </div>
                <div className="w-full bg-gray-800 h-2.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      data.abuse_score > 50 ? 'bg-red-500' : data.abuse_score > 20 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${data.abuse_score}%` }}
                  ></div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-gray-950/40 rounded-xl border border-gray-800/60">
                  <div className="flex items-center space-x-2 text-gray-400 text-xs mb-1">
                    <Globe className="w-3.5 h-3.5" />
                    <span>{t.threatModal.country}</span>
                  </div>
                  <p className="font-semibold text-white">{data.country}</p>
                </div>

                <div className="p-3 bg-gray-950/40 rounded-xl border border-gray-800/60">
                  <div className="flex items-center space-x-2 text-gray-400 text-xs mb-1">
                    <Server className="w-3.5 h-3.5" />
                    <span>{t.threatModal.usageType}</span>
                  </div>
                  <p className="font-semibold text-white truncate">{data.usage_type}</p>
                </div>
              </div>

              <div className="p-3 bg-gray-950/40 rounded-xl border border-gray-800/60">
                <p className="text-xs text-gray-400 mb-1">{t.threatModal.domain}</p>
                <p className="font-mono text-xs text-gray-200">{data.domain}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-gray-400">{t.threatModal.notFound}</p>
          )}

          {/* Action button */}
          <div className="pt-2">
            <button
              onClick={handleToggleBlock}
              disabled={actionLoading}
              className={`w-full py-2.5 px-4 rounded-xl font-medium text-sm transition shadow-lg flex items-center justify-center space-x-2 ${
                isBlocked
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20'
                  : 'bg-red-600 hover:bg-red-500 text-white shadow-red-600/20'
              }`}
            >
              {isBlocked ? (
                <>
                  <CheckCircle className="w-4 h-4" />
                  <span>{t.threatModal.btnUnblock}</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4" />
                  <span>{t.threatModal.btnBlock}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
