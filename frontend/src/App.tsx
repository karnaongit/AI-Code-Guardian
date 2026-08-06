import { useState } from 'react';
import ChatPanel from './components/ChatPanel';
import FindingsExplorer from './components/FindingsExplorer';
import AnalyticsDashboard from './components/AnalyticsDashboard';
import RequirementCoverage from './components/RequirementCoverage';
import { LayoutDashboard, MessageSquare, Search, ShieldCheck } from 'lucide-react';

function App() {
  const [activeTab, setActiveTab] = useState('chat');

  return (
    <div className="flex h-screen bg-slate-900 text-slate-100">
      {/* Sidebar */}
      <div className="w-64 bg-slate-800 border-r border-slate-700 p-4 flex flex-col">
        <h1 className="text-xl font-bold mb-8 text-blue-400">AI Code Guardian</h1>
        
        <nav className="flex flex-col gap-2">
          <button
            onClick={() => setActiveTab('chat')}
            className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${activeTab === 'chat' ? 'bg-blue-600' : 'hover:bg-slate-700'}`}
          >
            <MessageSquare size={20} />
            Chat Assistant
          </button>
          
          <button
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${activeTab === 'findings' ? 'bg-blue-600' : 'hover:bg-slate-700'}`}
          >
            <Search size={20} />
            Findings Explorer
          </button>
          
          <button
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${activeTab === 'analytics' ? 'bg-blue-600' : 'hover:bg-slate-700'}`}
          >
            <LayoutDashboard size={20} />
            Analytics
          </button>
          
          <button
            onClick={() => setActiveTab('requirements')}
            className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${activeTab === 'requirements' ? 'bg-blue-600' : 'hover:bg-slate-700'}`}
          >
            <ShieldCheck size={20} />
            Requirement Coverage
          </button>
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'chat' && <ChatPanel />}
        {activeTab === 'findings' && <FindingsExplorer />}
        {activeTab === 'analytics' && <AnalyticsDashboard />}
        {activeTab === 'requirements' && <RequirementCoverage />}
      </div>
    </div>
  );
}

export default App;
