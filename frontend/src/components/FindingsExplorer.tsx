import { useState, useEffect } from 'react';
import type { Finding } from '../api/client';
import { apiClient } from '../api/client';
import { FileText, AlertTriangle, Play, ShieldAlert, ChevronRight, X } from 'lucide-react';
import Editor from '@monaco-editor/react';

export default function FindingsExplorer() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);

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

  const triggerNewScan = async () => {
    try {
      setLoading(true);
      // Hardcoded for demo parity, wait, better use a prompt or default to current dir
      await apiClient.triggerScan("./", false);
      await loadFindings();
    } catch (e) {
      console.error(e);
      setLoading(false);
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
    <div className="flex h-full bg-slate-900 text-slate-200">
      <div className="flex-1 flex flex-col p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="text-blue-500" /> Repository Findings
          </h2>
          <button 
            onClick={triggerNewScan}
            disabled={loading}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition-colors font-medium text-white disabled:opacity-50"
          >
            <Play size={18} />
            Run New Scan
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
    </div>
  );
}
