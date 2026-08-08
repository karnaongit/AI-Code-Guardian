import { useState } from 'react';
import { Shield, FolderGit2, AlertTriangle, CheckCircle, Search } from 'lucide-react';

export default function Sidebar({ onAnalyze, loading, summary }) {
  const [repoInput, setRepoInput] = useState('');

  const handleAnalyze = (e) => {
    e.preventDefault();
    if (repoInput.trim()) {
      onAnalyze(repoInput.trim());
    }
  };

  return (
    <aside className="w-80 border-r border-gray-800 bg-gray-900/80 flex flex-col z-20">
      <div className="p-6 border-b border-gray-800">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="text-blue-500" size={28} />
          <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
            AI-Code Guardian
          </h1>
        </div>

        <form onSubmit={handleAnalyze} className="space-y-3">
          <div className="relative">
            <FolderGit2 className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
            <input
              type="text"
              placeholder="fportantier/vulpy"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-md py-2 pl-9 pr-4 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !repoInput.trim()}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 rounded-md transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading ? (
              <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
            ) : (
              <Search size={16} />
            )}
            {loading ? 'Analyzing...' : 'Scan Repository'}
          </button>
        </form>
      </div>

      {summary && (
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {hasReport && (
            <button 
              onClick={onHideSidebar}
              className="w-full bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium py-2 rounded-md transition-colors border border-gray-700 flex items-center justify-center gap-2"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 3H3v18h18V3zM9 21V9M3 15h18"/></svg>
              View Full Mindmap
            </button>
          )}

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Scan Overview</h3>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div className="bg-gray-800/50 p-3 rounded-lg border border-gray-800">
                <div className="text-2xl font-semibold text-gray-200">{summary.security_findings_count || 0}</div>
                <div className="text-xs text-gray-400">Security Findings</div>
              </div>
              <div className="bg-gray-800/50 p-3 rounded-lg border border-gray-800">
                <div className="text-2xl font-semibold text-blue-400">
                  {summary.repository_risk_score || 0}
                </div>
                <div className="text-xs text-gray-400">Security Score</div>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-800/50 p-3 rounded-lg border border-gray-800">
                <div className="text-xl font-semibold text-gray-300">{summary.files_scanned || 0}</div>
                <div className="text-xs text-gray-500">Files Scanned</div>
              </div>
              <div className="bg-gray-800/50 p-3 rounded-lg border border-gray-800">
                <div className="text-xl font-semibold text-gray-300">{summary.functions || 0}</div>
                <div className="text-xs text-gray-500">Functions</div>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Risk Assessment</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-gray-800/30 rounded-lg border border-gray-800/50">
                <div className="flex items-center gap-2">
                  <AlertTriangle className={summary.security_findings_count > 0 ? 'text-red-400' : 'text-green-400'} size={16} />
                  <span className="text-sm text-gray-300">Overall Risk</span>
                </div>
                <span className="text-sm font-medium">{summary.security_findings_count > 0 ? 'High' : 'Low'}</span>
              </div>
              <div className="flex items-center justify-between p-3 bg-gray-800/30 rounded-lg border border-gray-800/50">
                <div className="flex items-center gap-2">
                  <CheckCircle className={summary.security_findings_count > 0 ? 'text-red-400' : 'text-green-400'} size={16} />
                  <span className="text-sm text-gray-300">Merge Decision</span>
                </div>
                <span className="text-sm font-medium">{summary.security_findings_count > 0 ? 'BLOCK' : 'ALLOW'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
