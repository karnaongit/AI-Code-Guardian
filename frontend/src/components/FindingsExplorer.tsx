import { useState, useEffect } from 'react';
import type { Finding } from '../api/client';
import { apiClient } from '../api/client';
import { FileText, AlertTriangle, Play, ShieldAlert, ChevronRight, X, Folder, GitBranch, Sparkles, CheckCircle2 } from 'lucide-react';
import Editor from '@monaco-editor/react';

export default function FindingsExplorer() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);

  // Scan modal state
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanType, setScanType] = useState<'local' | 'github'>('local');
  const [targetPath, setTargetPath] = useState('./');
  const [repoUrl, setRepoUrl] = useState('');
  const [scanMode, setScanMode] = useState('precision');
  const [enableAi, setEnableAi] = useState(false);
  const [requirementsPath, setRequirementsPath] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanSuccessMsg, setScanSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    try {
      setLoading(true);
      const data = await apiClient.listFindings();
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectFinding = async (id: string) => {
    setSelectedFindingId(id);
    try {
      const data = await apiClient.getFindingDetail(id);
      setDetail(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setScanSuccessMsg(null);
    setScanning(true);

    try {
      const res = await apiClient.triggerScan({
        target_path: scanType === 'local' ? targetPath.trim() : undefined,
        repo_url: scanType === 'github' ? repoUrl.trim() : undefined,
        scan_mode: scanMode,
        enable_ai: enableAi,
        requirements: requirementsPath.trim() ? [requirementsPath.trim()] : undefined,
      });

      setScanSuccessMsg(`Scan completed successfully! ${res.total_findings ?? 0} findings discovered.`);
      setShowScanModal(false);
      await loadFindings();
    } catch (err: any) {
      setScanError(err.message || 'Scan failed. Check target path or server logs.');
    } finally {
      setScanning(false);
    }
  };

  const severityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10';
      case 'high': return 'text-orange-500 bg-orange-500/10';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10';
      default: return 'text-blue-500 bg-blue-500/10';
    }
  };

  return (
    <div className="flex h-full bg-slate-900 text-slate-200 relative">
      <div className="flex-1 flex flex-col p-6 overflow-hidden">
        {scanSuccessMsg && (
          <div className="mb-4 p-3 bg-emerald-900/30 border border-emerald-500/50 rounded-lg text-emerald-300 text-sm flex items-center justify-between">
            <span className="flex items-center gap-2">
              <CheckCircle2 size={16} /> {scanSuccessMsg}
            </span>
            <button onClick={() => setScanSuccessMsg(null)} className="text-emerald-400 hover:text-white">
              <X size={16} />
            </button>
          </div>
        )}

        <div className="flex justify-between items-center mb-6 shrink-0">
          <div>
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <ShieldAlert className="text-blue-500" /> Repository Findings
            </h2>
            <p className="text-xs text-slate-400 mt-1">Scan local codebases, GitHub repositories, or custom projects</p>
          </div>
          
          <button 
            onClick={() => setShowScanModal(true)}
            disabled={loading || scanning}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2.5 rounded-lg transition-colors font-semibold text-white shadow-lg shadow-blue-900/30 disabled:opacity-50"
          >
            <Play size={18} />
            Scan New Repository
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center flex-1">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <div className="bg-slate-800 rounded-xl overflow-hidden shadow-lg border border-slate-700 flex-1 overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-700/50 border-b border-slate-700 text-sm font-semibold">
                  <th className="p-4">Severity</th>
                  <th className="p-4">Category</th>
                  <th className="p-4">Location</th>
                  <th className="p-4">Rule</th>
                  <th className="p-4"></th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-slate-500">No findings available. Run a scan.</td>
                  </tr>
                )}
                {findings.map(f => (
                  <tr 
                    key={f.finding_id} 
                    onClick={() => handleSelectFinding(f.finding_id)}
                    className="border-b border-slate-700/50 hover:bg-slate-700/30 cursor-pointer transition-colors group"
                  >
                    <td className="p-4">
                      <span className={`px-2 py-1 rounded text-xs font-bold uppercase tracking-wider ${severityColor(f.severity)}`}>
                        {f.severity || 'INFO'}
                      </span>
                    </td>
                    <td className="p-4 font-medium">{f.category}</td>
                    <td className="p-4 text-slate-400 font-mono text-sm">
                      <div className="flex items-center gap-2">
                        <FileText size={14} />
                        {f.file_path}:{f.line_number}
                      </div>
                    </td>
                    <td className="p-4 text-slate-400">{f.rule_id}</td>
                    <td className="p-4 text-right">
                      <ChevronRight size={18} className="text-slate-500 group-hover:text-blue-400 transition-colors" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Drawer */}
      {selectedFindingId && detail && (
        <div className="w-1/3 bg-slate-800 border-l border-slate-700 shadow-2xl flex flex-col">
          <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/80 sticky top-0">
            <h3 className="font-bold text-lg flex items-center gap-2">
              <AlertTriangle className={severityColor(detail.severity).split(' ')[0]} />
              Finding Details
            </h3>
            <button onClick={() => setSelectedFindingId(null)} className="text-slate-400 hover:text-white p-1">
              <X size={20} />
            </button>
          </div>
          
          <div className="p-6 overflow-y-auto flex-1 space-y-6">
            <div>
              <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">Evidence ID</div>
              <div className="inline-block px-2 py-1 bg-blue-900/40 text-blue-300 font-mono text-sm rounded border border-blue-800/50">
                {detail.finding_id}
              </div>
            </div>

            <div>
              <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">Description</div>
              <p className="text-slate-200">{detail.description || detail.category}</p>
            </div>

            <div>
              <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-2 flex justify-between">
                <span>Code Snippet</span>
                <span className="normal-case opacity-70">{detail.file_path}:{detail.line_number}</span>
              </div>
              <div className="h-48 rounded-lg overflow-hidden border border-slate-700">
                <Editor
                  height="100%"
                  defaultLanguage="python"
                  theme="vs-dark"
                  value={detail.snippet || "// No snippet available"}
                  options={{ readOnly: true, minimap: { enabled: false }, scrollBeyondLastLine: false }}
                />
              </div>
            </div>

            <div>
              <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">Recommendation</div>
              <p className="text-slate-200 bg-slate-700/30 p-3 rounded-lg border border-slate-700/50">{detail.recommendation || "No specific recommendation provided."}</p>
            </div>
            
            <div className="flex gap-4">
               <div>
                  <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">CWE</div>
                  <div className="text-sm font-mono">{detail.cwe || 'N/A'}</div>
               </div>
               <div>
                  <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">Rule ID</div>
                  <div className="text-sm font-mono">{detail.rule_id || 'N/A'}</div>
               </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan Repository Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-800 border border-slate-700 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="p-5 border-b border-slate-700 flex justify-between items-center bg-slate-800/90">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg">
                  <Play size={20} />
                </div>
                <div>
                  <h3 className="font-bold text-lg text-slate-100">Scan Repository</h3>
                  <p className="text-xs text-slate-400">Provide a local directory or GitHub repository to trigger security scanning</p>
                </div>
              </div>
              <button 
                onClick={() => !scanning && setShowScanModal(false)}
                disabled={scanning}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-700 transition-colors disabled:opacity-50"
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleStartScan} className="p-6 space-y-5">
              {/* Type Switcher */}
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">Repository Source Format</label>
                <div className="grid grid-cols-2 gap-3 p-1 bg-slate-900/60 rounded-xl border border-slate-700/60">
                  <button
                    type="button"
                    onClick={() => setScanType('local')}
                    className={`flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg font-medium text-sm transition-all ${
                      scanType === 'local' 
                        ? 'bg-blue-600 text-white shadow-md' 
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Folder size={18} />
                    Local Directory Path
                  </button>

                  <button
                    type="button"
                    onClick={() => setScanType('github')}
                    className={`flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg font-medium text-sm transition-all ${
                      scanType === 'github' 
                        ? 'bg-blue-600 text-white shadow-md' 
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <GitBranch size={18} />
                    GitHub Repo URL
                  </button>
                </div>
              </div>

              {/* Input field based on selection */}
              {scanType === 'local' ? (
                <div>
                  <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Local Directory Path</label>
                  <div className="relative">
                    <input
                      type="text"
                      value={targetPath}
                      onChange={(e) => setTargetPath(e.target.value)}
                      placeholder="e.g. ./ or /Users/username/my-project"
                      required
                      className="w-full bg-slate-900 text-slate-100 rounded-xl px-4 py-3 border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                  </div>
                  <div className="flex gap-2 mt-2">
                    <span className="text-xs text-slate-500">Quick presets:</span>
                    <button type="button" onClick={() => setTargetPath('./')} className="text-xs text-blue-400 hover:underline font-mono">./ (Current Root)</button>
                    <button type="button" onClick={() => setTargetPath('./backend')} className="text-xs text-blue-400 hover:underline font-mono">./backend</button>
                    <button type="button" onClick={() => setTargetPath('./frontend')} className="text-xs text-blue-400 hover:underline font-mono">./frontend</button>
                  </div>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">GitHub Repository URL / Slug</label>
                  <input
                    type="text"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="e.g. https://github.com/appsecco/dvpwa or owner/repository"
                    required
                    className="w-full bg-slate-900 text-slate-100 rounded-xl px-4 py-3 border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                  />
                  <div className="flex gap-2 mt-2">
                    <span className="text-xs text-slate-500">Samples:</span>
                    <button type="button" onClick={() => setRepoUrl('https://github.com/appsecco/dvpwa')} className="text-xs text-blue-400 hover:underline font-mono">appsecco/dvpwa</button>
                  </div>
                </div>
              )}

              {/* Advanced Controls: Mode, AI Toggle, Requirements */}
              <div className="grid grid-cols-2 gap-4 pt-2 border-t border-slate-700/50">
                <div>
                  <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Scan Mode</label>
                  <select
                    value={scanMode}
                    onChange={(e) => setScanMode(e.target.value)}
                    className="w-full bg-slate-900 text-slate-100 rounded-xl px-3 py-2.5 border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                  >
                    <option value="precision">Precision (Focused & Fast)</option>
                    <option value="recall">Recall (Deep Comprehensive)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">AI Reasoning (Nemotron)</label>
                  <label className="flex items-center gap-2 p-2.5 bg-slate-900 rounded-xl border border-slate-700 cursor-pointer text-sm">
                    <input
                      type="checkbox"
                      checked={enableAi}
                      onChange={(e) => setEnableAi(e.target.checked)}
                      className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500 bg-slate-800 border-slate-600"
                    />
                    <Sparkles size={16} className="text-amber-400" />
                    <span>Enable AI Reasoning</span>
                  </label>
                </div>
              </div>

              {/* Requirements doc optional */}
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Business Requirements Document <span className="text-slate-500 font-normal">(Optional)</span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={requirementsPath}
                    onChange={(e) => setRequirementsPath(e.target.value)}
                    placeholder="e.g. docs/requirements.md or PRD spec path"
                    className="w-full bg-slate-900 text-slate-100 rounded-xl px-4 py-2.5 border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm font-mono"
                  />
                </div>
              </div>

              {/* Error Alert */}
              {scanError && (
                <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-xl text-red-300 text-xs flex items-start gap-2">
                  <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
                  <div>{scanError}</div>
                </div>
              )}

              {/* Modal Action Buttons */}
              <div className="flex justify-end gap-3 pt-4 border-t border-slate-700">
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  disabled={scanning}
                  className="px-4 py-2.5 rounded-xl border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors text-sm font-medium disabled:opacity-50"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  disabled={scanning}
                  className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition-all flex items-center gap-2 shadow-lg shadow-blue-900/30 disabled:opacity-50"
                >
                  {scanning ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      <span>Scanning Repository...</span>
                    </>
                  ) : (
                    <>
                      <Play size={16} />
                      <span>Start Security Scan</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

