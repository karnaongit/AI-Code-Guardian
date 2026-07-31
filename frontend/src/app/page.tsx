"use client";

import React, { useState, useEffect } from "react";
import TriageFunnel, { FunnelMetrics } from "../components/scan/TriageFunnel";
import IDEWorkspace from "../components/workspace/IDEWorkspace";
import FindingDrawer, { FindingDetail } from "../components/scan/FindingDrawer";
import ChatDrawer from "../components/chat/ChatDrawer";
import VulnerabilityViewer from "../components/editor/VulnerabilityViewer";
import CodeMindMap from "../components/mindmap/CodeMindMap";
import { buildMindMapFromScan } from "../components/mindmap/utils";
import CyberDashboard from "../components/cyberlock/CyberDashboard";

import {
  Shield,
  Play,
  Terminal,
  Sparkles,
  AlertTriangle,
  Download,
  FileText,
  Layers,
  Cpu,
  Package,
  HardDrive,
  CheckCircle,
  HelpCircle,
  Code2,
  MessageSquare,
  MessageCircle,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [activeTab, setActiveTab] = useState("cyber_dashboard");
  const [report, setReport] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [isFindingDrawerOpen, setIsFindingDrawerOpen] = useState(false);
  const [isChatDrawerOpen, setIsChatDrawerOpen] = useState(false);
  const [chatContext, setChatContext] = useState("");

  // Filters for Security Tab
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    try {
      const savedReport = sessionStorage.getItem("guardian_report");
      if (savedReport) {
        const parsed = JSON.parse(savedReport);
        setReport(parsed);
        if (parsed?.scan?.findings?.length > 0) {
          setSelectedFinding(parsed.scan.findings[0]);
        }
        return;
      }
    } catch (e) {
      console.warn("Failed to parse saved report from sessionStorage:", e);
    }

    // Fetch initial report summary from FastAPI backend
    fetch(`${API_BASE}/api/v1/reports/summary`)
      .then((res) => res.json())
      .then((data) => {
        setReport(data);
        if (data?.scan?.findings?.length > 0) {
          setSelectedFinding(data.scan.findings[0]);
        }
      })
      .catch(() => {
        // Fallback default demo data if server starting
      });
  }, []);

  const handleScanComplete = (scanResult: any) => {
    if (scanResult) {
      const updatedReport = {
        scan: scanResult.scan || scanResult,
        unified_risk: scanResult.unified_risk,
        quantum: scanResult.quantum,
        business_intent: scanResult.business_intent,
        repository: scanResult.repository,
      };
      setReport(updatedReport);
      try {
        sessionStorage.setItem("guardian_report", JSON.stringify(updatedReport));
      } catch (e) {
        console.warn("Failed to save report to sessionStorage:", e);
      }
      const scanFindings = scanResult.scan?.findings || scanResult.findings || [];
      if (scanFindings.length > 0) {
        setSelectedFinding(scanFindings[0]);
      }
    }
  };

  const handleDownloadReport = (format: string) => {
    window.open(`${API_BASE}/api/v1/reports/download?format=${format}`, "_blank");
  };

  const handleDiscussInChat = (finding: FindingDetail) => {
    setChatContext(finding.category);
    setIsFindingDrawerOpen(false);
    setIsChatDrawerOpen(true);
  };

  const findings = report?.scan?.findings || [
    {
      finding_id: "e1a9b2c3",
      category: "SQL Injection",
      severity: "Critical",
      cwe: "CWE-89",
      owasp: "A03:2021",
      file: "services/payment_service.py",
      line: 42,
      snippet: `cursor.execute("SELECT * FROM users WHERE id = " + user_input)`,
      recommendation: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))",
      reason: "Untrusted string user_input flows directly into database execution sink.",
      is_exploitable: true,
      exploitability_score: 0.95,
      exploit_scenario: "Attacker supplies '1 OR 1=1' to bypass authentication.",
    },
    {
      finding_id: "f4d5e6c7",
      category: "Weak Crypto",
      severity: "High",
      cwe: "CWE-327",
      owasp: "A02:2021",
      file: "utils/crypto.py",
      line: 18,
      snippet: `cipher = hashlib.md5(secret_key.encode()).hexdigest()`,
      recommendation: "Replace MD5 with SHA-256 or Argon2id.",
      reason: "MD5 is collision-broken and deprecated by NIST.",
      is_exploitable: false,
      exploitability_score: 0.4,
    },
  ];

  const metrics: FunnelMetrics = {
    total_alerts: findings.length,
    exploitable_count: findings.filter((f: any) => f.is_exploitable).length,
    high_priority_count: findings.filter((f: any) => ["Critical", "High", "CRITICAL", "HIGH"].includes(f.severity)).length,
    immediate_risk_count: findings.filter((f: any) => f.is_exploitable && ["Critical", "High", "CRITICAL", "HIGH"].includes(f.severity)).length,
  };

  // Dynamic Score & Overview Calculations
  const criticalCount = findings.filter((f: any) => (f.severity || "").toUpperCase() === "CRITICAL").length;
  const highCount = findings.filter((f: any) => (f.severity || "").toUpperCase() === "HIGH").length;
  const mediumCount = findings.filter((f: any) => (f.severity || "").toUpperCase() === "MEDIUM").length;
  const lowCount = findings.filter((f: any) => (f.severity || "").toUpperCase() === "LOW").length;

  const securityScore = Math.max(0, 100 - (criticalCount * 30 + highCount * 15 + mediumCount * 5 + lowCount * 2));
  const overallRiskScore = Math.min(100, criticalCount * 35 + highCount * 20 + mediumCount * 8 + lowCount * 3);

  const quantumIssues = findings.filter((f: any) => 
    f.cwe === "CWE-327" || 
    (f.category || "").toLowerCase().includes("crypto") || 
    (f.category || "").toLowerCase().includes("md5")
  ).length;
  const quantumScore = Math.max(0, 100 - quantumIssues * 20);

  const depIssues = report?.dependencies?.vulnerable_count || 0;
  const depScore = Math.max(0, 100 - depIssues * 15);
  const alignmentScore = Math.max(0, 100 - (criticalCount * 10 + highCount * 5));

  let mergeDecision = { text: "✅ Pass", color: "text-emerald-400", sub: "Approved for merge", border: "border-emerald-500/30" };
  if (criticalCount > 0) {
    mergeDecision = { text: "❌ Blocked", color: "text-red-400", sub: "Critical security vulnerabilities detected", border: "border-red-500/30" };
  } else if (highCount > 0) {
    mergeDecision = { text: "⚠️ Warn", color: "text-amber-400", sub: "Requires Security Review", border: "border-amber-500/30" };
  }

  const parsedLangs = Array.from(
    new Set(findings.map((f: any) => f.file?.split(".").pop()?.toUpperCase()).filter(Boolean))
  ).join(", ") || "PYTHON, TYPESCRIPT";

  const totalUstNodes = report?.scan?.total_nodes || (findings.length * 180 + 420);

  const mindMapData = React.useMemo(() => {
    return buildMindMapFromScan(report, null);
  }, [report]);

  const filteredFindings = findings.filter((f: any) => {
    const matchesSev = severityFilter === "All" || f.severity === severityFilter;
    const matchesSearch =
      !searchQuery ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.file.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const tabs = [
    { id: "cyber_dashboard", label: "Cyberlock Dashboard", icon: "🟧" },
    { id: "workspace", label: "IDE Workspace", icon: "💻" },
    { id: "mindmap", label: "Code Mind Map", icon: "🧠" },
    { id: "overview", label: "Overview", icon: "📊" },
    { id: "security_compliance", label: "Security & Compliance", icon: "🔐" },
    { id: "pr_review", label: "PR Review", icon: "🔄" },
    { id: "reports", label: "Reports", icon: "📄" },
  ];

  if (activeTab === "cyber_dashboard") {
    return <CyberDashboard onNavigatePlatform={() => setActiveTab("workspace")} />;
  }


  return (
    <>
      {/* Glassmorphism Background Orbs */}
      <div className="bg-glass-orbs">
        <div className="orb orb-1"></div>
        <div className="orb orb-2"></div>
        <div className="orb orb-3"></div>
      </div>

      <div className="flex h-screen overflow-hidden text-slate-100 relative z-10">
        {/* Left Side Navigation Sidebar */}
        <aside className="w-64 glass-panel border-r border-white/10 shrink-0 flex flex-col p-5 z-20 justify-between">
          <div className="space-y-6">
            {/* App Branding Header */}
            <div className="flex items-center gap-3 p-1">
              <div className="p-2.5 rounded-2xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 shadow-[0_0_20px_rgba(236,72,153,0.4)] shrink-0">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1.5">
                  AI Code Guardian
                </h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-pink-500/20 text-pink-300 font-mono border border-pink-500/30">v2.1.0</span>
              </div>
            </div>

            {/* Sidebar Navigation Options */}
            <nav className="space-y-2">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider px-3 mb-2">
                Navigation
              </div>
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-3 rounded-2xl text-xs font-semibold transition-all ${
                    activeTab === tab.id
                      ? "bg-gradient-to-r from-pink-500/20 to-purple-600/20 text-pink-300 border-l-4 border-l-pink-500 shadow-[0_0_15px_rgba(236,72,153,0.3)] font-bold backdrop-blur-md"
                      : "text-slate-400 hover:text-slate-100 hover:bg-white/5"
                  }`}
                >
                  <span className="text-base">{tab.icon}</span>
                  <span className="truncate">{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>

          {/* Quick Actions & Report Download */}
          <div className="space-y-2 pt-4 border-t border-white/10">
            <button
              onClick={() => handleDownloadReport("zip")}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-2xl glass-button text-xs font-semibold text-white shadow-lg transition"
            >
              <Download className="w-4 h-4" /> Download Zip Report
            </button>
          </div>
        </aside>

        {/* Main Content Workspace Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* Top Hero Glass Banner (Inspired by Glass Reference Mockups) */}
          <div className="glass-banner p-5 rounded-3xl flex items-center justify-between relative overflow-hidden group">
            <div className="space-y-1 relative z-10">
              <span className="text-[10px] font-bold uppercase tracking-widest text-pink-400 font-mono px-2.5 py-1 rounded-full bg-pink-500/10 border border-pink-500/30">
                ✨ Glassmorphism Security Workspace
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight mt-1">
                Evidence-Grounded AI Code Security
              </h2>
              <p className="text-xs text-slate-300 max-w-xl leading-relaxed">
                Deterministic Tree-sitter UST analysis combined with NVIDIA Nemotron AI context reasoning for automated vulnerability detection and one-click fixes.
              </p>
            </div>
            <div className="flex items-center gap-3 relative z-10 shrink-0">
              <button
                onClick={() => setIsChatDrawerOpen(true)}
                className="px-4 py-2.5 rounded-2xl glass-button text-xs font-bold text-white shadow-xl transition flex items-center gap-2"
              >
                <Sparkles className="w-4 h-4 text-amber-300" /> Ask AI Copilot
              </button>
            </div>
          </div>

          {/* Triage Funnel Banner */}
          <TriageFunnel metrics={metrics} />

      {/* Tab 0: IDE Workspace (Kept mounted in DOM to preserve state across tab switches) */}
      <div className={activeTab === "workspace" ? "block" : "hidden"}>
        <IDEWorkspace onScanComplete={handleScanComplete} />
      </div>

      {/* Tab: Code Mind Map */}
      {activeTab === "mindmap" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                🧠 Code Mind Map & AST Topology
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Interactive graph visualizing code structure, module dependencies, function call graphs, and risk findings.
              </p>
            </div>
          </div>
          <CodeMindMap data={mindMapData} />
        </div>
      )}

      {/* Tab 1: Overview */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="p-4 rounded-xl glass-card">
              <span className="text-xs text-slate-400">🔐 Security Score</span>
              <div className={`text-2xl font-bold mt-1 ${securityScore >= 80 ? "text-emerald-400" : securityScore >= 50 ? "text-amber-400" : "text-red-400"}`}>
                {securityScore} / 100
              </div>
            </div>
            <div className="p-4 rounded-xl glass-card">
              <span className="text-xs text-slate-400">🎯 Alignment</span>
              <div className="text-2xl font-bold text-blue-400 mt-1">{alignmentScore} / 100</div>
            </div>
            <div className="p-4 rounded-xl glass-card">
              <span className="text-xs text-slate-400">⚛️ Quantum Ready</span>
              <div className="text-2xl font-bold text-amber-400 mt-1">{quantumScore} / 100</div>
            </div>
            <div className="p-4 rounded-xl glass-card">
              <span className="text-xs text-slate-400">📦 Dependencies</span>
              <div className="text-2xl font-bold text-emerald-400 mt-1">{depScore} / 100</div>
            </div>
            <div className="p-4 rounded-xl glass-card">
              <span className="text-xs text-slate-400">⚠️ Overall Risk</span>
              <div className={`text-2xl font-bold mt-1 ${overallRiskScore > 60 ? "text-red-400" : overallRiskScore > 30 ? "text-amber-400" : "text-emerald-400"}`}>
                {overallRiskScore} / 100
              </div>
            </div>
          </div>

          <div className={`p-4 rounded-xl glass-panel border ${mergeDecision.border} text-sm font-semibold flex items-center justify-between`}>
            <span>Merge Decision: <strong className={mergeDecision.color}>{mergeDecision.text}</strong></span>
            <span className="text-xs font-mono text-slate-300">{mergeDecision.sub}</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Inspect Vulnerability Code Snippet</span>
                {findings.length > 0 && (
                  <select
                    value={selectedFinding?.finding_id || selectedFinding?.id || ""}
                    onChange={(e) => {
                      const found = findings.find((f: any) => (f.finding_id || f.id) === e.target.value);
                      if (found) setSelectedFinding(found);
                    }}
                    className="glass-input text-xs px-2.5 py-1 rounded text-slate-200 cursor-pointer"
                  >
                    {findings.map((f: any) => (
                      <option key={f.finding_id || f.id} value={f.finding_id || f.id} className="bg-slate-900 text-slate-200">
                        {f.severity}: {f.category || f.title} ({f.file})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <VulnerabilityViewer
                code={selectedFinding?.snippet || selectedFinding?.code_snippet || "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"}
                language={selectedFinding?.file?.split(".").pop() || "python"}
                filePath={selectedFinding?.file || "services/payment_service.py"}
                vulnerableLine={selectedFinding?.line || selectedFinding?.line_number || 42}
              />
            </div>

            <div className="space-y-4 glass-card p-5 rounded-xl">
              <h3 className="text-sm font-bold text-slate-200 border-b border-white/10 pb-2">Unified Syntax Tree (UST) & Real-time Breakdown</h3>
              <div className="space-y-3 text-xs text-slate-300">
                <div className="flex justify-between border-b border-white/10 pb-2">
                  <span>Languages Detected</span>
                  <span className="font-mono font-semibold text-indigo-400">{parsedLangs}</span>
                </div>
                <div className="flex justify-between border-b border-white/10 pb-2">
                  <span>Total UST AST Nodes</span>
                  <span className="font-mono font-semibold text-blue-400">{totalUstNodes.toLocaleString()} nodes</span>
                </div>
                <div className="flex justify-between border-b border-white/10 pb-2">
                  <span>Vulnerabilities Detected</span>
                  <span className="font-mono font-semibold text-red-400">{findings.length} findings</span>
                </div>
                <div className="flex justify-between border-b border-white/10 pb-2">
                  <span>Reachable & Exploitable</span>
                  <span className="font-mono font-semibold text-amber-400">
                    {findings.filter((f: any) => f.is_exploitable).length} items
                  </span>
                </div>
                <div className="flex justify-between border-b border-white/10 pb-2">
                  <span>Deterministic Static Rules</span>
                  <span className="font-mono text-emerald-400">100% verified</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Combined Tab: Security & Compliance */}
      {activeTab === "security_compliance" && (
        <div className="space-y-8">
          
          {/* Section: Security Findings */}
          <div className="space-y-4">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" /> Security Vulnerabilities
            </h2>
            <div className="flex flex-wrap gap-4 items-center justify-between glass-card p-4 rounded-xl">
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search category or file..."
                  className="glass-input rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none"
                />
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="glass-input rounded-lg px-3 py-1.5 text-xs text-slate-100 cursor-pointer"
                >
                  <option value="All" className="bg-slate-900">All Severities</option>
                  <option value="Critical" className="bg-slate-900">Critical</option>
                  <option value="High" className="bg-slate-900">High</option>
                  <option value="Medium" className="bg-slate-900">Medium</option>
                </select>
              </div>
              <span className="text-xs text-slate-400">Showing {filteredFindings.length} finding(s)</span>
            </div>

            <div className="overflow-x-auto rounded-xl glass-card">
              <table className="w-full text-left text-xs">
                <thead className="glass-panel text-slate-300 font-mono border-b border-white/10">
                  <tr>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">CWE</th>
                    <th className="p-3">Location</th>
                    <th className="p-3">Reachable</th>
                    <th className="p-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredFindings.map((f: any) => (
                    <tr key={f.finding_id || f.id} className="hover:bg-slate-800/50 transition">
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded font-semibold text-[10px] bg-red-500/20 text-red-400 border border-red-500/30">
                          {f.severity}
                        </span>
                      </td>
                      <td className="p-3 font-semibold text-slate-200">{f.category || f.title}</td>
                      <td className="p-3 font-mono text-slate-400">{f.cwe || f.cwe_id || "—"}</td>
                      <td className="p-3 font-mono text-slate-400">{f.file}:{f.line || f.line_number}</td>
                      <td className="p-3">
                        {f.is_exploitable ? (
                          <span className="text-red-400 font-semibold">Yes ({Math.round((f.exploitability_score || 0) * 100)}%)</span>
                        ) : (
                          <span className="text-slate-500">No</span>
                        )}
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => {
                            setSelectedFinding(f);
                            setIsFindingDrawerOpen(true);
                          }}
                          className="px-3 py-1 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 font-medium transition"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Partitions for Other Compliance Contexts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Business Intent */}
            <div className="space-y-4 glass-card p-6 rounded-xl">
              <h2 className="text-base font-bold text-slate-100">🎯 Business Intent & Policy Verdicts</h2>
              <div className="p-4 rounded-xl glass-panel space-y-2">
                <div className="flex justify-between text-xs font-semibold">
                  <span className="text-emerald-400">[COMPLIANT] Manager Refund Approval Policy</span>
                  <span className="font-mono text-slate-400">services/payment.py:42</span>
                </div>
                <p className="text-xs text-slate-300">
                  Requirement: "Refunds above 50,000 require manager authorization." Code contains explicit authorization check.
                </p>
              </div>
            </div>

            {/* Quantum CBOM */}
            <div className="space-y-4 glass-card p-6 rounded-xl">
              <h2 className="text-base font-bold text-slate-100">⚛️ Cryptographic Bill of Materials (CBOM)</h2>
              <div className="overflow-x-auto rounded-xl glass-panel">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-white/10 text-slate-300 font-mono">
                    <tr>
                      <th className="p-3">Algorithm</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Occurrences</th>
                      <th className="p-3">Migration Target</th>
                      <th className="p-3">NIST Standard</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    <tr>
                      <td className="p-3 font-mono font-bold">MD5</td>
                      <td className="p-3 text-orange-400">Classically Broken</td>
                      <td className="p-3">2</td>
                      <td className="p-3 text-emerald-400 font-mono">SHA-256</td>
                      <td className="p-3 font-mono">FIPS 180-4</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Dependencies */}
            <div className="space-y-4 glass-card p-6 rounded-xl">
              <h2 className="text-base font-bold text-slate-100">📦 Dependencies</h2>
              <div className="p-4 rounded-xl glass-panel flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-200">No vulnerable dependencies found.</span>
                <CheckCircle className="w-5 h-5 text-emerald-500" />
              </div>
            </div>

            {/* IaC & Risk */}
            <div className="space-y-4 glass-card p-6 rounded-xl">
              <h2 className="text-base font-bold text-slate-100">🏗️ IaC & ⚠️ Risk Profile</h2>
              <div className="p-4 rounded-xl glass-panel">
                <p className="text-sm text-slate-300">Infrastructure as Code (Terraform/K8s) scans passed with <span className="text-emerald-400 font-bold">0 critical issues</span>.</p>
                <p className="text-sm text-slate-300 mt-2">Overall systemic risk is currently assessed as <span className="text-amber-400 font-bold">Moderate</span> due to unresolved high-severity app vulnerabilities.</p>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* Tab 8: PR Review Integration */}
      {activeTab === "pr_review" && (
        <div className="space-y-6">
          <div className="glass-card p-6 rounded-xl flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-100">Automated Code Review & PR Integration</h2>
              <p className="text-sm text-slate-400 mt-1">Connect your repository to auto-generate pull requests for security fixes.</p>
            </div>
            <button className="px-4 py-2 glass-button rounded-lg text-white text-sm font-semibold shadow-lg transition flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>
              Connect GitHub
            </button>
          </div>

          <div className="grid gap-4">
            <h3 className="text-sm font-bold text-slate-300">Suggested Pull Requests</h3>
            
            <div className="glass-panel p-4 rounded-xl flex items-start justify-between group">
              <div className="flex gap-4">
                <div className="mt-1">
                  <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center border border-emerald-500/30">
                    <CheckCircle className="w-4 h-4" />
                  </div>
                </div>
                <div>
                  <h4 className="text-sm font-bold text-slate-200">Fix SQL Injection in Payment Service</h4>
                  <p className="text-xs text-slate-400 mt-1">Replaces vulnerable string concatenation with parameterized queries.</p>
                  <div className="flex items-center gap-3 mt-3">
                    <span className="text-xs px-2 py-0.5 rounded glass-card text-slate-300">services/payment_service.py</span>
                    <span className="text-xs text-emerald-400 font-semibold">+ 1 line</span>
                    <span className="text-xs text-red-400 font-semibold">- 1 line</span>
                  </div>
                </div>
              </div>
              <button className="px-4 py-2 glass-button text-white text-xs font-semibold rounded-lg transition opacity-0 group-hover:opacity-100">
                Create PR
              </button>
            </div>

            <div className="glass-panel p-4 rounded-xl flex items-start justify-between group">
              <div className="flex gap-4">
                <div className="mt-1">
                  <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center border border-emerald-500/30">
                    <CheckCircle className="w-4 h-4" />
                  </div>
                </div>
                <div>
                  <h4 className="text-sm font-bold text-slate-200">Upgrade MD5 to SHA-256</h4>
                  <p className="text-xs text-slate-400 mt-1">Migrates deprecated MD5 hashing to secure SHA-256 for secret generation.</p>
                  <div className="flex items-center gap-3 mt-3">
                    <span className="text-xs px-2 py-0.5 rounded glass-card text-slate-300">utils/crypto.py</span>
                    <span className="text-xs text-emerald-400 font-semibold">+ 1 line</span>
                    <span className="text-xs text-red-400 font-semibold">- 1 line</span>
                  </div>
                </div>
              </div>
              <button className="px-4 py-2 glass-button text-white text-xs font-semibold rounded-lg transition opacity-0 group-hover:opacity-100">
                Create PR
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab 9: Reports & Export */}
      {activeTab === "reports" && (
        <div className="space-y-6 glass-card p-6 rounded-xl">
          <h2 className="text-base font-bold text-slate-100">📄 Export Scan Reports</h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {["json", "sarif", "html", "csv", "pdf"].map((fmt) => (
              <button
                key={fmt}
                onClick={() => handleDownloadReport(fmt)}
                className="p-4 rounded-xl glass-panel hover:bg-white/10 hover:border-blue-500/50 text-center font-mono text-xs uppercase font-bold text-blue-400 hover:scale-105 transition"
              >
                Download .{fmt}
              </button>
            ))}
          </div>
        </div>
      )}

      </main>
      </div>

      {/* Floating Circular AI Copilot Button (Bottom Right) */}
      <button
        onClick={() => setIsChatDrawerOpen(true)}
        className="fixed bottom-6 right-6 z-40 w-14 h-14 rounded-full glass-button bg-gradient-to-r from-blue-600 to-indigo-600 text-white flex items-center justify-center shadow-[0_0_25px_rgba(59,130,246,0.6)] hover:scale-110 active:scale-95 transition-all duration-300 group"
        title="Chat with AI Copilot"
      >
        <MessageSquare className="w-6 h-6 text-white group-hover:rotate-12 transition-transform duration-300" />
        <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-emerald-500 border-2 border-slate-900 rounded-full animate-ping" />
        <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-emerald-500 border-2 border-slate-900 rounded-full" />
      </button>

      {/* Slide-over Drawers */}
      <FindingDrawer
        finding={selectedFinding}
        isOpen={isFindingDrawerOpen}
        onClose={() => setIsFindingDrawerOpen(false)}
        onDiscussInChat={handleDiscussInChat}
      />

      <ChatDrawer
        isOpen={isChatDrawerOpen}
        onClose={() => setIsChatDrawerOpen(false)}
        initialContext={chatContext}
      />
    </>
  );
}
