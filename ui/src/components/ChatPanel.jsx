import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { MessageSquare, X, Send, Bot, User, ShieldAlert, Zap, Search, ShieldCheck, Link2 } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';

const ACTIONS = [
  { id: 'EXPLAIN_FINDING', label: 'Explain Vulnerability', icon: ShieldAlert },
  { id: 'SHOW_EVIDENCE', label: 'Show Evidence', icon: Search },
  { id: 'GENERATE_FIX', label: 'Generate Secure Fix', icon: Zap },
  { id: 'VALIDATE_FIX', label: 'Validate Fix', icon: ShieldCheck },
  { id: 'SHOW_REFERENCES', label: 'Show References', icon: Link2 }
];

export default function ChatPanel({ findingNode, repoName, onClose }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState(null);
  const endOfMessagesRef = useRef(null);

  const findingId = findingNode?.id;

  useEffect(() => {
    if (findingId) {
      setSession(null);
      setMessages([]);
      
      const initSession = async () => {
        setLoading(true);
        try {
          const response = await axios.post('/analysis/investigate', { 
            finding_id: findingId, 
            repo_name: repoName 
          });
          setSession(response.data);
          
          setMessages([{
            role: 'assistant',
            isSummary: true,
            content: response.data.context.summary
          }]);
        } catch (error) {
          setMessages([{ 
            role: 'assistant', 
            content: "**Error:** Failed to initialize Investigation Session." 
          }]);
        } finally {
          setLoading(false);
        }
      };
      initSession();
    }
  }, [findingId, repoName]);

  useEffect(() => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const hasValidSecureFix = messages.some(msg => 
    msg.isResult && 
    msg.content && 
    typeof msg.content === 'object' && 
    ((typeof msg.content.secure_fix === 'string' && msg.content.secure_fix.trim() !== '') || 
     (typeof msg.content.secure_code === 'string' && msg.content.secure_code.trim() !== ''))
  );

  const handleAction = async (actionId) => {
    if (!session || loading) return;
    
    if (actionId === 'VALIDATE_FIX' && !hasValidSecureFix) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "**Notice:** Generate a secure fix before validating it."
      }]);
      return;
    }
    
    const actionDef = ACTIONS.find(a => a.id === actionId);
    setMessages(prev => [...prev, { role: 'user', content: actionDef.label }]);
    setLoading(true);
    
    try {
      const response = await axios.post('/analysis/action', {
        session_id: session.session_id,
        action: actionId,
        repo_name: repoName,
        finding_id: findingId
      });
      
      setMessages(prev => [...prev, {
        role: 'assistant',
        isResult: true,
        content: response.data
      }]);
    } catch (error) {
      const errorMsg = error.response?.data?.detail || "Failed to execute action.";
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: `**Error:** ${errorMsg}` 
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleSend = async (e) => {
    e.preventDefault();
  };

  const renderSummary = (summary) => (
    <div className="bg-gray-800/80 rounded-lg p-4 text-sm border border-gray-700 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-white text-base leading-tight mr-2">{summary.title}</h3>
        <span className={`px-2 py-1 rounded text-xs font-semibold shrink-0 ${
          summary.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
          summary.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
          summary.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
          'bg-blue-500/20 text-blue-400 border border-blue-500/30'
        }`}>{summary.severity}</span>
      </div>
      
      <div className="grid grid-cols-2 gap-3 text-gray-300 border-t border-b border-gray-800 py-3">
        <div className="col-span-2">
          <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">File</span>
          <span className="font-mono text-xs bg-gray-950 px-2 py-1 rounded border border-gray-800 block truncate" title={summary.file}>{summary.file}</span>
        </div>
        <div>
          <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Class</span>
          <span className="font-mono text-xs text-purple-400 truncate block">{summary.class_name || '-'}</span>
        </div>
        <div>
          <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Function</span>
          <span className="font-mono text-xs text-amber-400 truncate block">{summary.function_name || '-'}</span>
        </div>
        <div>
          <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Line</span>
          <span className="font-mono text-xs text-gray-200">{summary.line || '-'}</span>
        </div>
        <div>
          <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Confidence</span>
          <span className="font-mono text-xs text-blue-400">{summary.confidence || '1.0'}</span>
        </div>
      </div>
      
      {(summary.cwe || summary.owasp) && (
        <div className="text-gray-300 flex gap-4 text-xs">
          {summary.cwe && <div><span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">CWE</span><span className="bg-gray-850 px-1.5 py-0.5 rounded text-gray-300 border border-gray-800">{summary.cwe}</span></div>}
          {summary.owasp && <div><span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">OWASP</span><span className="bg-gray-850 px-1.5 py-0.5 rounded text-gray-300 border border-gray-800">{summary.owasp}</span></div>}
        </div>
      )}
      
      <div>
        <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Evidence</span>
        <p className="text-gray-300 bg-gray-950 p-2.5 rounded border border-gray-800 font-mono text-xs whitespace-pre-wrap">{summary.evidence || summary.description}</p>
      </div>

      <div>
        <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Recommendation</span>
        <p className="text-gray-300 text-xs leading-relaxed">{summary.recommendation}</p>
      </div>
    </div>
  );

  const safeMarkdown = (val) => {
    if (!val) return '';
    if (typeof val === 'string') return val;
    if (Array.isArray(val)) return val.map(v => typeof v === 'string' ? v : JSON.stringify(v)).join('\n\n');
    if (typeof val === 'object') return JSON.stringify(val, null, 2);
    return String(val);
  };

  const renderResult = (result) => {
    if (!result) return null;
    
    if (typeof result === 'string') {
      return <ReactMarkdown className="prose prose-invert prose-sm">{result}</ReactMarkdown>;
    }
    
    return (
      <div className="space-y-4">
        {result.policy_decision && (
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-sm mb-6">
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Security Analysis</h4>
            <div className="flex items-center gap-4 mb-4">
              <div className="flex-1">
                <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Decision</span>
                <span className={`inline-flex items-center px-2.5 py-1 rounded text-sm font-bold ${
                  result.policy_decision.decision === 'BLOCK' ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                  result.policy_decision.decision === 'WARN' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/30' :
                  'bg-green-500/20 text-green-500 border border-green-500/30'
                }`}>
                  {result.policy_decision.decision}
                </span>
              </div>
              <div className="flex-1 border-l border-gray-800 pl-4">
                <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Reachable</span>
                <span className={`inline-flex items-center text-sm font-semibold ${
                  result.policy_decision.reachable ? 'text-orange-400' : 'text-gray-400'
                }`}>
                  {result.policy_decision.reachable ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="flex-1 border-l border-gray-800 pl-4">
                <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-1">Reason Code</span>
                <span className="font-mono text-[10px] text-gray-300">
                  {result.policy_decision.reason_code}
                </span>
              </div>
            </div>
            
            {result.policy_decision.reachable && result.policy_decision.endpoint && (
              <div className="mt-3 pt-3 border-t border-gray-800">
                <span className="text-[10px] text-gray-500 uppercase font-semibold block mb-2">API Endpoint</span>
                <div className="bg-gray-950 rounded border border-gray-800 p-2 text-xs font-mono">
                  <span className="text-blue-400 font-bold mr-2">{result.policy_decision.endpoint.method || 'API'}</span>
                  <span className="text-gray-300">{result.policy_decision.endpoint.route || result.policy_decision.endpoint.name}</span>
                </div>
              </div>
            )}
          </div>
        )}
        
        {result.summary && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Summary</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.summary)}</ReactMarkdown></div>
          </div>
        )}
        {result.root_cause && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Root Cause</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.root_cause)}</ReactMarkdown></div>
          </div>
        )}
        {result.attack_scenario && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Attack Scenario</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.attack_scenario)}</ReactMarkdown></div>
          </div>
        )}
        {result.evidence && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Evidence</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.evidence)}</ReactMarkdown></div>
          </div>
        )}
        {result.business_impact && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Business Impact</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.business_impact)}</ReactMarkdown></div>
          </div>
        )}
        {result.secure_fix && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Secure Fix</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.secure_fix)}</ReactMarkdown></div>
          </div>
        )}
        {result.secure_code && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Secure Code</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.secure_code)}</ReactMarkdown></div>
          </div>
        )}
        {result.validation_steps && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Validation Steps</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.validation_steps)}</ReactMarkdown></div>
          </div>
        )}
        {result.references && (
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">References</h4>
            <div className="text-gray-200 text-sm"><ReactMarkdown>{safeMarkdown(result.references)}</ReactMarkdown></div>
          </div>
        )}
      </div>
    );
  };

  return (
    <AnimatePresence>
      {findingId && (
        <motion.aside
          initial={{ x: '100%', opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: '100%', opacity: 0 }}
          transition={{ type: 'spring', damping: 25, stiffness: 200 }}
          className="w-[450px] border-l border-gray-800 bg-gray-900/95 backdrop-blur shadow-2xl flex flex-col z-30 absolute right-0 top-0 bottom-0"
        >
          <header className="h-14 border-b border-gray-800 flex items-center justify-between px-4 shrink-0 bg-gray-900">
            <div className="flex items-center gap-2">
              <MessageSquare className="text-blue-500" size={18} />
              <h2 className="font-semibold text-sm">Investigation Copilot</h2>
            </div>
            <button 
              onClick={onClose}
              className="p-1 hover:bg-gray-800 rounded-md text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </header>

          <div className="flex-1 overflow-y-auto flex flex-col">
            <div className="flex-1 p-4 space-y-6 overflow-y-auto">
              {messages.map((msg, idx) => (
                <div key={idx} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-1 ${
                    msg.role === 'user' ? 'bg-blue-600' : 'bg-blue-900/40 text-blue-400 border border-blue-800/50'
                  }`}>
                    {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                  </div>
                  <div className={`max-w-[85%] ${
                    msg.role === 'user' 
                      ? 'bg-blue-600 text-white rounded-lg p-3 rounded-tr-none' 
                      : ''
                  }`}>
                    {msg.isSummary ? renderSummary(msg.content) : 
                     msg.isResult ? renderResult(msg.content) : 
                     <span className="text-sm">{msg.content}</span>}
                  </div>
                </div>
              ))}
              
              {loading && (
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full bg-blue-900/40 text-blue-400 border border-blue-800/50 flex items-center justify-center shrink-0">
                    <Bot size={16} />
                  </div>
                  <div className="p-3 flex items-center gap-1.5 h-10">
                    <div className="w-2 h-2 bg-blue-500/50 rounded-full animate-bounce" />
                    <div className="w-2 h-2 bg-blue-500/50 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                    <div className="w-2 h-2 bg-blue-500/50 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                  </div>
                </div>
              )}
              <div ref={endOfMessagesRef} className="h-4" />
            </div>
          </div>

          <div className="p-3 border-t border-gray-800 bg-gray-900/50 shrink-0">
            <div className="flex flex-wrap gap-2 mb-3">
              {ACTIONS.map(action => {
                const isValidateFix = action.id === 'VALIDATE_FIX';
                const isDisabled = loading || !session || (isValidateFix && !hasValidSecureFix);
                
                return (
                  <button
                    key={action.id}
                    onClick={() => handleAction(action.id)}
                    disabled={isDisabled}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed border border-gray-700 rounded-md text-xs text-gray-300 transition-colors"
                  >
                    <action.icon size={14} className="text-blue-400" />
                    {action.label}
                  </button>
                );
              })}
            </div>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}
