import React, { useState } from 'react';
import { RuleItem } from '../types';
import { 
  toggleRule, saveRule, bulkToggleRules, 
  fetchSuricataSample, importSuricataRules,
  fetchETCategories, fetchAndImportETCategory 
} from '../api';
import {
  SlidersHorizontal, Plus, Shield, Check, Globe, Lock,
  Search, Skull, Waves, UploadCloud, CheckSquare, Square, DownloadCloud, FileText, AlertCircle, RefreshCw
} from 'lucide-react';
import { Language, translations } from '../i18n';

interface RulesPageProps {
  rules: RuleItem[];
  onRefreshRules: () => void;
  lang: Language;
}

export const RulesPage: React.FC<RulesPageProps> = ({ rules, onRefreshRules, lang }) => {
  const t = translations[lang];

  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [editingRule, setEditingRule] = useState<Partial<RuleItem> | null>(null);
  const [loadingAction, setLoadingAction] = useState(false);

  // Suricata Importer states
  const [showSuricataModal, setShowSuricataModal] = useState(false);
  const [suricataText, setSuricataText] = useState('');
  const [suricataLoading, setSuricataLoading] = useState(false);
  const [suricataMsg, setSuricataMsg] = useState<string | null>(null);
  const [etCategories, setEtCategories] = useState<Array<{ id: string; name: string; desc: string }>>([]);
  const [selectedETCategory, setSelectedETCategory] = useState<string>('emerging-scan.rules');
  const [maxRulesToFetch, setMaxRulesToFetch] = useState<number>(50);
  const [fetchingCategory, setFetchingCategory] = useState<boolean>(false);

  // Form states for creating custom rules visually
  const [ruleName, setRuleName] = useState('');
  const [ruleDesc, setRuleDesc] = useState('');
  const [ruleCategory, setRuleCategory] = useState('web_security');
  const [ruleSeverity, setRuleSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [conditionType, setConditionType] = useState('port_match');
  const [targetPort, setTargetPort] = useState('8080');
  const [thresholdCount, setThresholdCount] = useState('5');
  const [windowSeconds, setWindowSeconds] = useState('5');
  const [mitreAttack, setMitreAttack] = useState('T1059');

  const categories = [
    { id: 'all', label: t.rules.categories.all, icon: <Shield className="w-4 h-4" /> },
    { id: 'web_phishing', label: t.rules.categories.web_phishing, icon: <Globe className="w-4 h-4 text-blue-400" /> },
    { id: 'credential_access', label: t.rules.categories.credential_access, icon: <Lock className="w-4 h-4 text-emerald-400" /> },
    { id: 'reconnaissance', label: t.rules.categories.reconnaissance, icon: <Search className="w-4 h-4 text-amber-400" /> },
    { id: 'command_and_control', label: t.rules.categories.command_and_control, icon: <Skull className="w-4 h-4 text-red-400" /> },
    { id: 'denial_of_service', label: t.rules.categories.denial_of_service, icon: <Waves className="w-4 h-4 text-purple-400" /> },
    { id: 'exfiltration', label: t.rules.categories.exfiltration, icon: <UploadCloud className="w-4 h-4 text-cyan-400" /> },
  ];

  const handleToggle = async (ruleId: string, currentStatus: boolean) => {
    try {
      await toggleRule(ruleId, !currentStatus);
      onRefreshRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleBulkToggleCategory = async (cat: string | null, enable: boolean) => {
    setLoadingAction(true);
    try {
      await bulkToggleRules(undefined, cat === 'all' ? undefined : cat || undefined, enable);
      onRefreshRules();
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleOpenWizard = () => {
    setRuleName(lang === 'vi' ? 'Quy tắc bảo vệ Web tùy chỉnh' : 'Custom Web Protection Rule');
    setRuleDesc(lang === 'vi' ? 'Phát hiện kết nối web đáng ngờ trên cổng tùy chọn.' : 'Detects suspicious web connections on custom port.');
    setRuleCategory('web_security');
    setRuleSeverity('high');
    setConditionType('port_match');
    setTargetPort('8080');
    setThresholdCount('5');
    setWindowSeconds('5');
    setMitreAttack('T1059');

    setEditingRule({
      id: `rule-${Math.floor(100 + Math.random() * 900)}`,
      enabled: true
    });
  };

  const handleSaveWizard = async () => {
    if (!editingRule) return;

    let conditionObj: any = {};
    if (conditionType === 'port_match') {
      const portsArr = targetPort.split(',').map(p => parseInt(p.trim())).filter(n => !isNaN(n));
      conditionObj = { type: 'port_match', ports: portsArr.length ? portsArr : [8080] };
    } else if (conditionType === 'single_target_rate') {
      conditionObj = {
        type: 'single_target_rate',
        target_port: parseInt(targetPort) || 22,
        threshold_count: parseInt(thresholdCount) || 5,
        window_seconds: parseInt(windowSeconds) || 5,
        group_by: 'src_ip'
      };
    } else if (conditionType === 'threshold') {
      conditionObj = {
        type: 'threshold',
        field: 'dst_port',
        threshold_count: parseInt(thresholdCount) || 15,
        window_seconds: parseInt(windowSeconds) || 10,
        group_by: 'src_ip'
      };
    }

    const payload: Partial<RuleItem> = {
      id: editingRule.id,
      name: ruleName,
      description: ruleDesc,
      severity: ruleSeverity,
      category: ruleCategory,
      enabled: true,
      condition: conditionObj,
      action: { alert: true, block_ip: false },
      mitre_attack: mitreAttack,
      tags: ['user_defined', ruleCategory]
    };

    try {
      await saveRule(payload);
      setEditingRule(null);
      onRefreshRules();
    } catch (e) {
      console.error(e);
    }
  };

  const handleOpenSuricataModal = async () => {
    setShowSuricataModal(true);
    setSuricataMsg(null);
    if (etCategories.length === 0) {
      try {
        const cats = await fetchETCategories();
        setEtCategories(cats);
        if (cats.length > 0) setSelectedETCategory(cats[0].id);
      } catch (e) {
        console.error("Failed to load ET categories", e);
      }
    }
    if (!suricataText.trim()) {
      try {
        const sample = await fetchSuricataSample();
        setSuricataText(sample);
      } catch (err) {
        console.error(err);
      }
    }
  };

  const handleFetchOnlineCategory = async () => {
    setFetchingCategory(true);
    setSuricataMsg(null);
    try {
      const res = await fetchAndImportETCategory(selectedETCategory, maxRulesToFetch);
      const catObj = etCategories.find(c => c.id === selectedETCategory);
      setSuricataMsg(
        lang === 'vi'
          ? `Đã tải & nạp thành công ${res.imported_count} quy tắc từ "${catObj?.name || selectedETCategory}"!`
          : `Successfully fetched and imported ${res.imported_count} rules from "${catObj?.name || selectedETCategory}"!`
      );
      onRefreshRules();
    } catch (err: any) {
      setSuricataMsg(`Error: ${err.message}`);
    } finally {
      setFetchingCategory(false);
    }
  };

  const handleLoadSampleRules = async () => {
    try {
      const sample = await fetchSuricataSample();
      setSuricataText(sample);
      setSuricataMsg(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleExecuteImport = async () => {
    if (!suricataText.trim()) return;
    setSuricataLoading(true);
    setSuricataMsg(null);
    try {
      const res = await importSuricataRules(suricataText);
      setSuricataMsg(`${lang === 'vi' ? 'Đã nhập thành công' : 'Successfully imported'} ${res.imported_count} ${lang === 'vi' ? 'quy tắc Suricata!' : 'Suricata rules!'}`);
      onRefreshRules();
    } catch (err: any) {
      setSuricataMsg(`Error: ${err.message}`);
    } finally {
      setSuricataLoading(false);
    }
  };

  const filteredRules = rules.filter(r => {
    if (selectedCategory === 'all') return true;
    return r.category === selectedCategory;
  });

  const activeCount = rules.filter(r => r.enabled).length;

  const severityBadges: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner & Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 glass-panel p-5 rounded-2xl border border-gray-800">
        <div>
          <div className="flex items-center space-x-2">
            <SlidersHorizontal className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg font-bold text-white">{t.rules.title}</h2>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-semibold">
              {activeCount} / {rules.length} {t.rules.activeRatio}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t.rules.subtitle}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleBulkToggleCategory(selectedCategory, true)}
            disabled={loadingAction}
            className="flex items-center space-x-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 text-xs font-semibold px-3 py-2 rounded-xl transition"
          >
            <CheckSquare className="w-3.5 h-3.5" />
            <span>{t.rules.enableAll}</span>
          </button>

          <button
            onClick={() => handleBulkToggleCategory(selectedCategory, false)}
            disabled={loadingAction}
            className="flex items-center space-x-1 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-semibold px-3 py-2 rounded-xl transition"
          >
            <Square className="w-3.5 h-3.5" />
            <span>{t.rules.disableAll}</span>
          </button>

          {/* Suricata Import Button */}
          <button
            onClick={handleOpenSuricataModal}
            className="flex items-center space-x-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold px-4 py-2 rounded-xl shadow-lg shadow-purple-600/30 transition"
          >
            <DownloadCloud className="w-4 h-4" />
            <span>{t.rules.importSuricata}</span>
          </button>

          <button
            onClick={handleOpenWizard}
            className="flex items-center space-x-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-4 py-2 rounded-xl shadow-lg shadow-blue-600/20 transition"
          >
            <Plus className="w-4 h-4" />
            <span>{t.rules.addCustomRule}</span>
          </button>
        </div>
      </div>

      {/* Category Selection Filter Pills */}
      <div className="flex items-center space-x-2 overflow-x-auto custom-scrollbar pb-2">
        {categories.map(cat => (
          <button
            key={cat.id}
            onClick={() => setSelectedCategory(cat.id)}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition ${
              selectedCategory === cat.id
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'bg-gray-900/80 text-gray-400 hover:text-white hover:bg-gray-800 border border-gray-800'
            }`}
          >
            {cat.icon}
            <span>{cat.label}</span>
          </button>
        ))}
      </div>

      {/* Rule Preset Catalog Checklist Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            onClick={() => handleToggle(rule.id, rule.enabled)}
            className={`p-4 rounded-2xl border glass-panel transition duration-200 cursor-pointer flex items-start space-x-4 ${
              rule.enabled
                ? 'border-blue-500/30 bg-blue-500/5 hover:border-blue-500/50'
                : 'border-gray-800/80 opacity-60 hover:opacity-100 hover:border-gray-700'
            }`}
          >
            {/* Checkbox */}
            <div className="pt-0.5">
              <div
                className={`w-5 h-5 rounded-md flex items-center justify-center border transition ${
                  rule.enabled
                    ? 'bg-blue-600 border-blue-500 text-white shadow-md shadow-blue-600/30'
                    : 'border-gray-700 bg-gray-900 text-transparent'
                }`}
              >
                <Check className="w-3.5 h-3.5 stroke-[3]" />
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono font-bold text-blue-400">{rule.id}</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border uppercase ${severityBadges[rule.severity] || severityBadges.medium}`}>
                  {rule.severity}
                </span>
                {rule.mitre_attack && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                    {rule.mitre_attack}
                  </span>
                )}
              </div>
              <h3 className="font-semibold text-white text-sm">{rule.name}</h3>
              <p className="text-xs text-gray-400 leading-relaxed">{rule.description}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Suricata Import Modal */}
      {showSuricataModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fadeIn">
          <div className="bg-gray-900 border border-gray-800 w-full max-w-2xl rounded-2xl shadow-2xl p-6 glass-panel space-y-4 max-h-[90vh] overflow-y-auto custom-scrollbar">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2">
                <DownloadCloud className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">{t.rules.suricataModal.title}</h3>
              </div>
              <button onClick={() => setShowSuricataModal(false)} className="text-gray-400 hover:text-white text-xs">
                {t.rules.suricataModal.close}
              </button>
            </div>

            <p className="text-xs text-gray-400 leading-relaxed">
              {t.rules.suricataModal.desc}
            </p>

            {/* SECTION 1: Emerging Threats Open Categories (Live Remote Repository) */}
            <div className="bg-purple-950/20 border border-purple-800/40 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-purple-300 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-purple-400" />
                  <span>{t.rules.suricataModal.categoryLabel}</span>
                </span>
                <span className="text-[10px] text-purple-400/80 font-mono bg-purple-900/40 px-2 py-0.5 rounded-full border border-purple-700/30">
                  rules.emergingthreats.net (50,000+ rules)
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
                <div className="md:col-span-3">
                  <select
                    value={selectedETCategory}
                    onChange={(e) => setSelectedETCategory(e.target.value)}
                    className="w-full bg-gray-950 border border-purple-900/60 rounded-xl p-2.5 text-xs text-purple-200 outline-none focus:border-purple-400 font-mono"
                  >
                    {etCategories.map(cat => (
                      <option key={cat.id} value={cat.id} className="bg-gray-900 text-white">
                        {cat.name} ({cat.id})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <div className="flex items-center bg-gray-950 border border-purple-900/60 rounded-xl px-2.5 py-1.5">
                    <span className="text-[10px] text-gray-400 mr-2 whitespace-nowrap">{t.rules.suricataModal.fetchLimit}</span>
                    <input
                      type="number"
                      min={10}
                      max={200}
                      value={maxRulesToFetch}
                      onChange={(e) => setMaxRulesToFetch(parseInt(e.target.value) || 50)}
                      className="w-full bg-transparent text-xs text-white font-mono outline-none text-right"
                    />
                  </div>
                </div>
              </div>

              <p className="text-[11px] text-gray-400 italic">
                {etCategories.find(c => c.id === selectedETCategory)?.desc}
              </p>

              <button
                onClick={handleFetchOnlineCategory}
                disabled={fetchingCategory}
                className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-purple-600 hover:bg-purple-500 disabled:opacity-50 transition shadow-lg shadow-purple-600/30 flex items-center justify-center space-x-2"
              >
                {fetchingCategory ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>{t.rules.suricataModal.fetchingCategory}</span>
                  </>
                ) : (
                  <>
                    <DownloadCloud className="w-3.5 h-3.5" />
                    <span>{t.rules.suricataModal.fetchCategoryBtn}</span>
                  </>
                )}
              </button>
            </div>

            {/* SECTION 2: Manual Paste or Offline Testing */}
            <div className="space-y-2 pt-2 border-t border-gray-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-300 font-mono flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-blue-400" />
                  <span>{t.rules.suricataModal.orPasteManually}</span>
                </span>
                <button
                  onClick={handleLoadSampleRules}
                  className="text-xs text-blue-400 hover:text-blue-300 hover:underline font-mono"
                >
                  {t.rules.suricataModal.loadSample}
                </button>
              </div>

              <textarea
                rows={5}
                value={suricataText}
                onChange={(e) => setSuricataText(e.target.value)}
                placeholder={t.rules.suricataModal.placeholder}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs text-gray-200 font-mono focus:border-purple-500 outline-none custom-scrollbar"
              />

              <div className="flex justify-end">
                <button
                  onClick={handleExecuteImport}
                  disabled={suricataLoading || !suricataText.trim()}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gray-800 hover:bg-gray-700 disabled:opacity-50 border border-gray-700 transition flex items-center space-x-1.5"
                >
                  <Check className="w-3.5 h-3.5 text-blue-400" />
                  <span>{suricataLoading ? t.rules.suricataModal.importing : t.rules.suricataModal.importBtn}</span>
                </button>
              </div>
            </div>

            {suricataMsg && (
              <div className={`p-3 rounded-xl border text-xs flex items-center space-x-2 ${
                suricataMsg.startsWith('Error') 
                  ? 'bg-red-500/10 border-red-500/30 text-red-400' 
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}>
                <Check className="w-4 h-4 shrink-0" />
                <span>{suricataMsg}</span>
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-gray-800">
              <button
                onClick={() => setShowSuricataModal(false)}
                className="px-5 py-2 rounded-xl text-xs font-medium text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 transition"
              >
                {t.rules.suricataModal.close}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Visual Rule Creation Wizard Modal */}
      {editingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
          <div className="bg-gray-900 border border-gray-800 w-full max-w-lg rounded-2xl shadow-2xl p-6 glass-panel space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2">
                <Plus className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-bold text-white">{t.rules.wizard.title}</h3>
              </div>
              <button onClick={() => setEditingRule(null)} className="text-gray-400 hover:text-white text-xs">
                {t.rules.wizard.close}
              </button>
            </div>

            <div className="space-y-3.5 text-xs">
              <div>
                <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.ruleTitle}</label>
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white focus:border-blue-500 outline-none"
                  placeholder={t.rules.wizard.ruleTitlePlaceholder}
                />
              </div>

              <div>
                <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.desc}</label>
                <input
                  type="text"
                  value={ruleDesc}
                  onChange={(e) => setRuleDesc(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white focus:border-blue-500 outline-none"
                  placeholder={t.rules.wizard.descPlaceholder}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.category}</label>
                  <select
                    value={ruleCategory}
                    onChange={(e) => setRuleCategory(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white focus:border-blue-500 outline-none"
                  >
                    <option value="web_security">{t.rules.categories.web_phishing}</option>
                    <option value="credential_access">{t.rules.categories.credential_access}</option>
                    <option value="reconnaissance">{t.rules.categories.reconnaissance}</option>
                    <option value="command_and_control">{t.rules.categories.command_and_control}</option>
                    <option value="denial_of_service">{t.rules.categories.denial_of_service}</option>
                    <option value="exfiltration">{t.rules.categories.exfiltration}</option>
                  </select>
                </div>

                <div>
                  <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.severity}</label>
                  <select
                    value={ruleSeverity}
                    onChange={(e) => setRuleSeverity(e.target.value as any)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white focus:border-blue-500 outline-none"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.pattern}</label>
                <select
                  value={conditionType}
                  onChange={(e) => setConditionType(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white focus:border-blue-500 outline-none font-mono"
                >
                  <option value="port_match">{t.rules.wizard.patternPortMatch}</option>
                  <option value="single_target_rate">{t.rules.wizard.patternSingleRate}</option>
                  <option value="threshold">{t.rules.wizard.patternThreshold}</option>
                </select>
              </div>

              {conditionType === 'port_match' && (
                <div>
                  <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.targetPorts}</label>
                  <input
                    type="text"
                    value={targetPort}
                    onChange={(e) => setTargetPort(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white font-mono focus:border-blue-500 outline-none"
                    placeholder="e.g. 8080, 8443, 1337"
                  />
                </div>
              )}

              {conditionType !== 'port_match' && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.thresholdCount}</label>
                    <input
                      type="number"
                      value={thresholdCount}
                      onChange={(e) => setThresholdCount(e.target.value)}
                      className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white font-mono focus:border-blue-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.windowSeconds}</label>
                    <input
                      type="number"
                      value={windowSeconds}
                      onChange={(e) => setWindowSeconds(e.target.value)}
                      className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white font-mono focus:border-blue-500 outline-none"
                    />
                  </div>
                </div>
              )}

              <div>
                <label className="text-gray-300 block mb-1 font-medium">{t.rules.wizard.mitreCode}</label>
                <input
                  type="text"
                  value={mitreAttack}
                  onChange={(e) => setMitreAttack(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-white font-mono focus:border-blue-500 outline-none"
                  placeholder="e.g. T1059"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-3 border-t border-gray-800">
              <button
                onClick={() => setEditingRule(null)}
                className="px-4 py-2 rounded-xl text-xs font-medium text-gray-400 hover:text-white bg-gray-800"
              >
                {t.rules.wizard.cancel}
              </button>
              <button
                onClick={handleSaveWizard}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-600/20 flex items-center space-x-1"
              >
                <Check className="w-4 h-4" />
                <span>{t.rules.wizard.save}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
