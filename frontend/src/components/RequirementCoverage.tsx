import { useState, useEffect } from 'react';
import type { RequirementCoverage, RequirementVerdict } from '../api/client';
import { apiClient } from '../api/client';
import { FileText, CheckCircle, XCircle, HelpCircle, ShieldCheck } from 'lucide-react';

export default function RequirementCoveragePanel() {
  const [coverage, setCoverage] = useState<RequirementCoverage | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCoverage();
  }, []);

  const loadCoverage = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getRequirementCoverage();
      setCoverage(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict?.toLowerCase()) {
      case 'compliant': return <CheckCircle className="text-green-500" size={20} />;
      case 'violation': return <XCircle className="text-red-500" size={20} />;
      default: return <HelpCircle className="text-slate-500" size={20} />;
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict?.toLowerCase()) {
      case 'compliant': return 'text-green-500 bg-green-500/10 border-green-500/20';
      case 'violation': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'potential_violation': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      default: return 'text-slate-400 bg-slate-800 border-slate-700';
    }
  };

  return (
    <div className="flex h-full bg-slate-900 text-slate-200 p-6 flex-col">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck className="text-purple-500" /> Business Intent & Requirement Coverage
        </h2>
        <button 
          onClick={loadCoverage}
          disabled={loading}
          className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg transition-colors font-medium border border-slate-700 disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center flex-1">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div>
        </div>
      ) : !coverage || coverage.status === 'no_requirements' || coverage.status === 'no_scans' ? (
        <div className="flex-1 flex flex-col items-center justify-center bg-slate-800/50 rounded-xl border border-slate-700/50">
          <FileText className="text-slate-600 mb-4" size={48} />
          <h3 className="text-xl font-bold text-slate-400 mb-2">No Requirements Found</h3>
          <p className="text-slate-500 text-center max-w-md">
            The current scan does not have any attached business requirements or the scan hasn't completed yet. Provide requirements when triggering a scan.
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-6 flex-1 overflow-hidden">
          {/* Top Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col justify-center items-center">
              <div className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-2">Alignment Score</div>
              <div className="text-4xl font-bold text-white flex items-baseline gap-1">
                {coverage.alignment_score.toFixed(1)}<span className="text-xl text-slate-500">%</span>
              </div>
            </div>
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col justify-center items-center">
              <div className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-2">Policies Evaluated</div>
              <div className="text-4xl font-bold text-white">{Object.keys(coverage.policies || {}).length}</div>
            </div>
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col justify-center items-center">
              <div className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-2">Violations</div>
              <div className="text-4xl font-bold text-red-500">
                {coverage.verdicts.filter(v => v.verdict.toLowerCase().includes('violation')).length}
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="bg-slate-800 rounded-xl overflow-hidden shadow-lg border border-slate-700 flex-1 flex flex-col">
            <div className="p-4 border-b border-slate-700 bg-slate-800/80">
              <h3 className="font-bold text-lg">Requirement Evaluation Matrix</h3>
            </div>
            <div className="flex-1 overflow-y-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-700/50 border-b border-slate-700 text-sm font-semibold">
                    <th className="p-4 w-12 text-center">Status</th>
                    <th className="p-4">Business Requirement</th>
                    <th className="p-4">Action</th>
                    <th className="p-4">Required Control</th>
                    <th className="p-4">Matched Functions</th>
                  </tr>
                </thead>
                <tbody>
                  {coverage.verdicts.map((v: RequirementVerdict, i: number) => {
                    const pol = coverage.policies[v.policy_id];
                    return (
                      <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                        <td className="p-4 flex justify-center">{getVerdictIcon(v.verdict)}</td>
                        <td className="p-4">
                          <div className="font-medium text-slate-200 mb-1">{pol?.plain_english || v.policy}</div>
                          <div className="text-xs text-slate-500 font-mono italic">"{v.requirement}"</div>
                        </td>
                        <td className="p-4">
                          <span className="px-2 py-1 bg-slate-900 text-slate-300 rounded border border-slate-700 text-xs font-mono">
                            {pol?.action || "unknown"}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className="px-2 py-1 bg-purple-900/20 text-purple-400 rounded border border-purple-800/30 text-xs font-semibold tracking-wide">
                            {pol?.required_control || "unknown"}
                          </span>
                        </td>
                        <td className="p-4 text-sm text-slate-400">
                          {v.implementations?.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {v.implementations.map((imp, idx) => (
                                <span key={idx} className={`px-2 py-1 rounded border text-xs font-mono ${
                                  v.missing_control_in?.includes(imp.function) 
                                    ? 'bg-red-900/20 text-red-400 border-red-800/30' 
                                    : 'bg-green-900/20 text-green-400 border-green-800/30'
                                }`}>
                                  {imp.function}()
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-slate-500 italic">No implementations found</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {coverage.verdicts.length === 0 && (
                    <tr>
                      <td colSpan={5} className="p-8 text-center text-slate-500">No evaluations to display.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
