import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Activity, Shield, FolderGit2, Search, Loader, Upload } from 'lucide-react';
import RepositoryTree from './components/RepositoryTree';
import SourceCodeViewer from './components/SourceCodeViewer';
import ChatPanel from './components/ChatPanel';
import ExecutionTreeView from './components/ExecutionTreeView';

function App() {
  const [repoName, setRepoName] = useState('');
  const [repoInput, setRepoInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [selectedEntryPointId, setSelectedEntryPointId] = useState(null);
  const [showEntryModal, setShowEntryModal] = useState(false);
  
  const [selectedNode, setSelectedNode] = useState(null);
  const [isInvestigationOpen, setIsInvestigationOpen] = useState(false);
  const [centerMode, setCenterMode] = useState('code'); // 'code' or 'mindmap'
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const fileInputRef = useRef(null);

  const handleZipUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    setLoading(true);
    setRepoInput(file.name);
    setRepoName(file.name);
    
    try {
      const formData = new FormData();
      formData.append("file", file);
      
      const response = await axios.post('/analysis/repository/zip', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      
      const data = response.data;
      setReport(data);
      
      if (data.entry_points && data.entry_points.length > 1) {
        setShowEntryModal(true);
      } else if (data.entry_points && data.entry_points.length === 1) {
        setSelectedEntryPointId(data.entry_points[0].id);
      } else {
        setSelectedEntryPointId(null);
      }
      
      setSelectedNode(null);
      setIsInvestigationOpen(false);
      setCenterMode('mindmap');
      setIsSidebarOpen(true);
    } catch (error) {
      console.error("Failed to analyze ZIP:", error);
      alert("ZIP Analysis failed. Please check the backend.");
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const analyzeRepository = async (e) => {
    e?.preventDefault();
    if (!repoInput.trim()) return;
    
    setLoading(true);
    setRepoName(repoInput.trim());
    try {
      const response = await axios.post('/analysis/repository', { repo_name: repoInput.trim() });
      setReport(response.data);
      
      // If there are multiple entry points, prompt the user.
      if (response.data.entry_points && response.data.entry_points.length > 1) {
        setShowEntryModal(true);
      } else if (response.data.entry_points && response.data.entry_points.length === 1) {
        setSelectedEntryPointId(response.data.entry_points[0].id);
      } else {
        setSelectedEntryPointId(null);
      }
      
      // Wait for the user to select a File or Finding from the sidebar.
      setSelectedNode(null);
      setIsInvestigationOpen(false);
      setCenterMode('mindmap'); // Default to mindmap on new scan 
      setIsSidebarOpen(true);
    } catch (error) {
      console.error("Failed to analyze repository:", error);
      alert("Analysis failed. Please check the backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleNodeSelect = (node) => {
    setSelectedNode(node);
    const nodeType = node?.type || node?.node_type;
    
    // Auto-open investigation panel if finding is clicked
    if (nodeType === 'Finding') {
      setIsInvestigationOpen(true);
    }
  };

  useEffect(() => {
    const handleOpenInvestigation = () => setIsInvestigationOpen(true);
    window.addEventListener('open-investigation', handleOpenInvestigation);
    return () => window.removeEventListener('open-investigation', handleOpenInvestigation);
  }, []);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-gray-950 text-gray-100 font-sans">
      {/* Top Navbar / Header */}
      <header className="h-14 border-b border-gray-800 bg-[#18181b] flex items-center justify-between px-6 shrink-0 z-20">
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="p-1 hover:bg-gray-800 rounded text-gray-400 hover:text-white"
            title="Toggle Sidebar"
          >
            <FolderGit2 size={18} />
          </button>
          <Shield className="text-blue-500" size={24} />
          <h1 className="font-semibold text-lg tracking-tight bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
            AI-Code Guardian
          </h1>
          {report?.summary && (
            <div className="ml-6 pl-6 border-l border-gray-700 flex items-center gap-6 text-xs text-gray-400">
              <div className="flex gap-1.5"><span className="text-gray-500">Score:</span><span className="text-blue-400 font-bold">{Math.max(0, 100 - (report.summary.security_findings_count * 5))}</span></div>
              <div className="flex gap-1.5"><span className="text-gray-500">Files:</span><span className="text-gray-200">{report.summary.files_scanned}</span></div>
              <div className="flex gap-1.5" title={`Critical: ${report.summary.critical_findings || 0} | High: ${report.summary.high_findings || 0} | Medium: ${report.summary.medium_findings || 0} | Low: ${report.summary.low_findings || 0}`}>
                <span className="text-gray-500">Findings:</span>
                <span className={report.summary.security_findings_count > 0 ? "text-red-400 font-bold" : "text-green-400"}>
                  {report.summary.security_findings_count}
                </span>
                {report.summary.security_findings_count > 0 && (
                  <span className="flex gap-1 text-[10px] ml-1 items-center border border-gray-700 rounded px-1.5 bg-gray-900">
                    {report.summary.critical_findings > 0 && <span className="text-purple-400" title="Critical">C:{report.summary.critical_findings}</span>}
                    {report.summary.high_findings > 0 && <span className="text-red-400" title="High">H:{report.summary.high_findings}</span>}
                    {report.summary.medium_findings > 0 && <span className="text-orange-400" title="Medium">M:{report.summary.medium_findings}</span>}
                    {report.summary.low_findings > 0 && <span className="text-blue-400" title="Low">L:{report.summary.low_findings}</span>}
                  </span>
                )}
              </div>
              
              <div className="flex items-center bg-gray-900 rounded border border-gray-800 ml-4">
                <button 
                  onClick={() => setCenterMode('code')} 
                  className={`px-3 py-1 text-xs font-semibold transition-colors rounded-l border-r border-gray-800 ${centerMode === 'code' ? 'bg-blue-600 text-white' : 'hover:bg-gray-800'}`}
                >
                  Source Code
                </button>
                <button 
                  onClick={() => setCenterMode('mindmap')} 
                  className={`px-3 py-1 text-xs font-semibold transition-colors rounded-r ${centerMode === 'mindmap' ? 'bg-blue-600 text-white' : 'hover:bg-gray-800'}`}
                >
                  Execution Tree
                </button>
              </div>
            </div>
          )}
        </div>
        
        <form onSubmit={analyzeRepository} className="flex items-center gap-2 w-96">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={14} />
            <input
              type="text"
              placeholder="Github Link/(or upload ZIP 👉)"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
              className="w-full bg-[#27272a] border border-gray-700 rounded py-1.5 pl-9 pr-3 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-gray-500"
              disabled={loading}
            />
          </div>
          
          <input 
            type="file" 
            accept=".zip" 
            className="hidden" 
            ref={fileInputRef} 
            onChange={handleZipUpload} 
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={loading}
            title="Upload local repository ZIP"
            className="bg-[#27272a] border border-gray-700 hover:bg-gray-700 text-gray-300 px-2 py-1.5 rounded transition-colors disabled:opacity-50 flex items-center justify-center"
          >
            <Upload size={14} />
          </button>

          <button
            type="submit"
            disabled={loading || !repoInput.trim()}
            className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded transition-colors disabled:opacity-50 flex items-center gap-1 text-sm font-medium"
          >
            {loading ? <Loader className="animate-spin" size={14} /> : <span>Scan</span>}
          </button>
        </form>
      </header>
      
      {/* 3-Pane Layout */}
      <main className="flex-1 flex overflow-hidden">
        {/* Left Pane: Repository Tree */}
        <aside 
          className={`shrink-0 border-r border-gray-800 bg-[#18181b] flex flex-col transition-all duration-300 ${isSidebarOpen ? 'w-[280px]' : 'w-0 border-none'}`}
        >
          <div className="w-[280px] h-full flex flex-col overflow-hidden">
            {report ? (
              <RepositoryTree 
                report={report} 
                onNodeSelect={handleNodeSelect} 
                selectedNodeId={selectedNode?.id} 
              />
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-500 text-sm p-8 text-center bg-[#18181b]">
                {loading ? "Analyzing repository, please wait..." : "Scan a repository to build the explorer tree."}
              </div>
            )}
          </div>
        </aside>

        {/* Center Pane: Source Code Viewer / Mindmap */}
        <section className="flex-1 flex flex-col min-w-0 bg-[#1e1e1e] relative">
          {report && centerMode === 'mindmap' ? (
            <ExecutionTreeView 
              selectedNode={selectedNode}
              report={report}
              onNodeSelect={handleNodeSelect} 
              selectedEntryPointId={selectedEntryPointId}
            />
          ) : (
            <SourceCodeViewer 
              selectedNode={selectedNode}
              repoName={repoName}
              report={report}
            />
          )}
        </section>

        {/* Right Pane: Investigation Chat */}
        {isInvestigationOpen && selectedNode && (
          <aside className="w-96 shrink-0 border-l border-gray-800 bg-[#18181b] flex flex-col">
            <ChatPanel 
              findingNode={selectedNode} 
              repoName={repoName} 
              onClose={() => setIsInvestigationOpen(false)}
            />
          </aside>
        )}
      </main>

      {/* Entry Point Selection Modal */}
      {showEntryModal && report && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#18181b] border border-gray-800 rounded-lg shadow-xl w-full max-w-md overflow-hidden">
            <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
              <h2 className="text-lg font-semibold text-gray-200">Select Application Entry Point</h2>
            </div>
            <div className="p-4">
              <p className="text-sm text-gray-400 mb-4">
                Multiple entry points were detected. Which one would you like to use for the Global Execution Tree?
              </p>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {report.entry_points.map((ep) => (
                  <button
                    key={ep.id}
                    onClick={() => {
                      setSelectedEntryPointId(ep.id);
                      setShowEntryModal(false);
                    }}
                    className="w-full text-left px-4 py-3 rounded border border-gray-800 hover:border-blue-500 hover:bg-blue-500/10 transition-colors flex justify-between items-center"
                  >
                    <span className="font-medium text-gray-200">{ep.name}</span>
                    <span className="text-xs text-gray-500 font-mono truncate max-w-[200px] ml-4">{ep.path}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="p-4 border-t border-gray-800 flex justify-end bg-gray-900/50">
              <button 
                onClick={() => setShowEntryModal(false)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-sm transition-colors"
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
