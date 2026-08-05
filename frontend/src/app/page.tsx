"use client";

import React, { useState, useEffect, useCallback, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
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
  Sparkles,
  Download,
  CheckCircle,
  MessageSquare,
  Bot,
  LayoutDashboard,
  Code2,
  Network,
  BarChart2,
  Lock,
  GitPullRequest,
  FileText,
  AlertTriangle,
  ChevronRight,
  Activity,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TABS = [
  { id: "cyber_dashboard", label: "Dashboard",          icon: LayoutDashboard },
  { id: "workspace",       label: "IDE Workspace",       icon: Code2 },
  { id: "mindmap",         label: "Mind Map",            icon: Network },
  { id: "overview",        label: "Overview",            icon: BarChart2 },
  { id: "security_compliance", label: "Security",        icon: Lock },
  { id: "pr_review",       label: "PR Review",           icon: GitPullRequest },
  { id: "reports",         label: "Reports",             icon: FileText },
];

/* ─── Animated page wrapper ─────────────────────────────────────── */
function PageTransition({ children, tabKey }: { children: React.ReactNode; tabKey: string }) {
  return (
    <div
      key={tabKey}
      className="animate-in fade-in-0 slide-in-from-bottom-1 duration-200 ease-out"
    >
      {children}
    </div>
  );
}

/* ─── Section heading helper ─────────────────────────────────────── */
function SectionHead({ title }: { title: string }) {
  return (
    <div className="flex items-center gap-2.5 mb-5">
      <span className="w-1.5 h-1.5 rounded-full bg-[#ff5400] flex-shrink-0" />
      <h2 className="text-[10px] font-mono font-bold uppercase tracking-[0.22em] text-[#f4f4f8]">{title}</h2>
    </div>
  );
}

/* ─── Inner app (needs useSearchParams, must be inside Suspense) ──── */
function AppInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const getTabFromURL = useCallback(() => {
    const t = searchParams.get("tab");
    return TABS.some((x) => x.id === t) ? t! : "cyber_dashboard";
  }, [searchParams]);

  const [activeTab, setActiveTab] = useState(getTabFromURL);
  const [report, setReport] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [isFindingDrawerOpen, setIsFindingDrawerOpen] = useState(false);
  const [isChatDrawerOpen, setIsChatDrawerOpen] = useState(false);
  const [chatContext, setChatContext] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  /* Sync URL → state when user hits back/forward */
  useEffect(() => {
    setActiveTab(getTabFromURL());
  }, [searchParams, getTabFromURL]);

  /* Navigate and push URL history so back button works */
  const navigateTo = useCallback(
    (tabId: string) => {
      const params = new URLSearchParams(searchParams.toString());
      params.set("tab", tabId);
      router.push(`?${params.toString()}`);
    },
    [router, searchParams]
  );

  /* Load report */
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem("guardian_report");
      if (saved) {
        const parsed = JSON.parse(saved);
        setReport(parsed);
        if (parsed?.scan?.findings?.length > 0) setSelectedFinding(parsed.scan.findings[0]);
        return;
      }
    } catch (e) {
      console.warn("sessionStorage read failed:", e);
    }
    fetch(`${API_BASE}/api/v1/reports/summary`)
      .then((r) => r.json())
      .then((d) => {
        setReport(d);
        if (d?.scan?.findings?.length > 0) setSelectedFinding(d.scan.findings[0]);
      })
      .catch(() => {});
  }, []);

  const handleScanComplete = (scanResult: any) => {
    if (!scanResult) return;
    const updated = {
      scan: scanResult.scan || scanResult,
      unified_risk: scanResult.unified_risk,
      quantum: scanResult.quantum,
      business_intent: scanResult.business_intent,
      repository: scanResult.repository,
    };
    setReport(updated);
    try { sessionStorage.setItem("guardian_report", JSON.stringify(updated)); } catch {}
    const sf = (updated.scan?.findings || updated.findings || [])[0];
    if (sf) setSelectedFinding(sf);
  };

  const handleDownloadReport = (fmt: string) =>
    window.open(`${API_BASE}/api/v1/reports/download?format=${fmt}`, "_blank");

  const handleDiscussInChat = (f: FindingDetail) => {
    setChatContext(f.category);
    setIsFindingDrawerOpen(false);
    setIsChatDrawerOpen(true);
  };

  /* ── Derived data ─────────────────────────────── */
  const findings: any[] = report?.scan?.findings || [
    { finding_id:"e1a9b2c3", category:"SQL Injection", severity:"Critical", cwe:"CWE-89", owasp:"A03:2021", file:"services/payment_service.py", line:42, snippet:`cursor.execute("SELECT * FROM users WHERE id = " + user_input)`, recommendation:"Use parameterized queries.", reason:"Untrusted user_input flows directly into DB sink.", is_exploitable:true, exploitability_score:0.95, exploit_scenario:"Attacker supplies '1 OR 1=1' to bypass auth." },
    { finding_id:"f4d5e6c7", category:"Weak Crypto",   severity:"High",     cwe:"CWE-327", owasp:"A02:2021", file:"utils/crypto.py",              line:18, snippet:`cipher = hashlib.md5(secret_key.encode()).hexdigest()`,           recommendation:"Replace MD5 with SHA-256 or Argon2id.",         reason:"MD5 is collision-broken.",                                 is_exploitable:false, exploitability_score:0.4 },
  ];

  const critical = findings.filter((f) => f.severity?.toUpperCase() === "CRITICAL").length;
  const high     = findings.filter((f) => f.severity?.toUpperCase() === "HIGH").length;
  const medium   = findings.filter((f) => f.severity?.toUpperCase() === "MEDIUM").length;
  const low      = findings.filter((f) => f.severity?.toUpperCase() === "LOW").length;

  const securityScore   = Math.max(0, 100 - (critical*30 + high*15 + medium*5 + low*2));
  const overallRiskScore= Math.min(100, critical*35 + high*20 + medium*8 + low*3);
  const quantumScore    = Math.max(0, 100 - findings.filter((f) => f.cwe==="CWE-327" || (f.category||"").toLowerCase().includes("crypto")).length*20);
  const depScore        = Math.max(0, 100 - (report?.dependencies?.vulnerable_count||0)*15);
  const alignmentScore  = Math.max(0, 100 - (critical*10 + high*5));

  const mergeDecision = critical > 0
    ? { text:"BLOCKED", color:"text-red-400", sub:"Critical vulnerabilities detected", border:"border-red-500/25" }
    : high > 0
      ? { text:"REVIEW",  color:"text-amber-400", sub:"Requires security review",        border:"border-amber-500/25" }
      : { text:"PASS",    color:"text-emerald-400", sub:"Approved for merge",             border:"border-emerald-500/25" };

  const parsedLangs = Array.from(new Set(findings.map((f) => f.file?.split(".").pop()?.toUpperCase()).filter(Boolean))).join(", ") || "PY, TS";
  const totalUstNodes = report?.scan?.total_nodes || (findings.length * 180 + 420);

  const mindMapData = React.useMemo(() => buildMindMapFromScan(report, null), [report]);

  const metrics: FunnelMetrics = {
    total_alerts: findings.length,
    exploitable_count: findings.filter((f) => f.is_exploitable).length,
    high_priority_count: findings.filter((f) => ["Critical","High","CRITICAL","HIGH"].includes(f.severity)).length,
    immediate_risk_count: findings.filter((f) => f.is_exploitable && ["Critical","High","CRITICAL","HIGH"].includes(f.severity)).length,
  };

  const filteredFindings = findings.filter((f) => {
    const ms = severityFilter === "All" || f.severity === severityFilter;
    const mq = !searchQuery || f.category.toLowerCase().includes(searchQuery.toLowerCase()) || f.file.toLowerCase().includes(searchQuery.toLowerCase());
    return ms && mq;
  });

  /* ── Dashboard full-screen shortcut ────────────── */
  if (activeTab === "cyber_dashboard") {
    return <CyberDashboard onNavigatePlatform={() => navigateTo("workspace")} />;
  }


  /* ── Sidebar ─────────────────────────────────────── */
  return (
    <>
      <div className="bg-glass-orbs" aria-hidden />

      <div className="flex h-screen overflow-hidden text-[#f4f4f8] relative z-10">

        {/* ── Sidebar ─────────────────────────────── */}
        <aside
          className={`bg-[#08090d] border-r border-white/7 shrink-0 flex flex-col z-20 overflow-hidden transition-all duration-300 ease-in-out ${
            sidebarOpen ? "w-56" : "w-0"
          }`}
        >
          {/* Brand */}
          <div className="px-5 pt-5 pb-4 border-b border-white/7">
            <button onClick={() => navigateTo("cyber_dashboard")} className="flex items-center gap-2.5 group w-full">
              <div className="w-8 h-8 rounded-lg bg-[#12131a] border border-[#ff5400]/30 flex items-center justify-center shrink-0 group-hover:border-[#ff5400]/60 transition-colors">
                <Shield className="w-4 h-4 text-[#ff5400]" />
              </div>
              <div className="text-left">
                <div className="text-[11px] font-mono font-bold tracking-widest text-[#f4f4f8] leading-tight">
                  AI CODE <span className="text-[#ff5400]">GUARDIAN</span>
                </div>
                <div className="text-[9px] font-mono text-[#8e8e9a] mt-0.5">v2.1.0 · PLATFORM</div>
              </div>
            </button>
          </div>

          {/* Live status chip */}
          <div className="px-5 py-3 border-b border-white/7">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/8 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-subtle shrink-0" />
              <span className="text-[9px] font-mono font-semibold text-emerald-400 tracking-wider">ENGINE ONLINE</span>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/60 uppercase tracking-[0.25em] px-2 mb-3">
              Navigation
            </div>
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => navigateTo(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-[11px] font-mono font-semibold transition-all duration-200 ease-out active:scale-[0.98] relative group ${
                    isActive
                      ? "bg-[#ff5400]/12 text-[#ff5400] shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]"
                      : "text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/6"
                  }`}
                >
                  {/* Active left bar */}
                  {isActive && (
                    <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r-full bg-[#ff5400] shadow-[0_0_8px_#ff5400] transition-all duration-200" />
                  )}
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#ff5400]" : "text-[#8e8e9a] group-hover:text-[#f4f4f8]"} transition-colors duration-200`} />
                  <span className="truncate tracking-wide">{tab.label}</span>
                  {isActive && <ChevronRight className="w-3 h-3 ml-auto shrink-0 text-[#ff5400]/60 animate-in fade-in slide-in-from-left-1 duration-200" />}
                </button>
              );
            })}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t border-white/7">
            <button
              onClick={() => handleDownloadReport("zip")}
              className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg glass-button text-[10px] font-mono font-bold tracking-wider transition"
            >
              <Download className="w-3.5 h-3.5" /> DOWNLOAD
            </button>
          </div>
        </aside>

        {/* ── Main ─────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto bg-[#0B0F19]">

          {/* Sticky top bar */}
          <header className="sticky top-0 z-10 bg-[#0B0F19]/95 backdrop-blur-sm border-b border-white/7 px-6 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* Sidebar toggle */}
              <button
                onClick={() => setSidebarOpen((v) => !v)}
                className="flex items-center justify-center w-7 h-7 rounded-md text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/6 transition-all duration-150"
                title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
              >
                {sidebarOpen
                  ? <PanelLeftClose className="w-4 h-4" />
                  : <PanelLeftOpen className="w-4 h-4" />}
              </button>
              {/* Breadcrumb */}
              <span className="text-[#8e8e9a] font-mono text-[10px]">Platform</span>
              <ChevronRight className="w-3 h-3 text-[#8e8e9a]/50" />
              <span className="text-[#f4f4f8] font-mono text-[10px] font-semibold">
                {TABS.find(t => t.id === activeTab)?.label}
              </span>
            </div>
            <div className="flex items-center gap-3">
              {/* Scan stats pills */}
              <div className="hidden sm:flex items-center gap-2">
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/8 border border-red-500/20 text-[9px] font-mono font-semibold text-red-400">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  {critical} CRITICAL
                </div>
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#ff5400]/8 border border-[#ff5400]/20 text-[9px] font-mono font-semibold text-[#ff5400]">
                  <Zap className="w-2.5 h-2.5" />
                  {high} HIGH
                </div>
              </div>
            </div>
          </header>

          {/* Scrollable content */}
          <div className="p-6 space-y-5">

            {/* Triage funnel — always visible */}
            <TriageFunnel metrics={metrics} />

            {/* ── Tab content with fade-in transition ─ */}
            <PageTransition tabKey={activeTab}>

              {/* IDE Workspace */}
              {activeTab === "workspace" && (
                <IDEWorkspace onScanComplete={handleScanComplete} />
              )}

              {/* Mind Map */}
              {activeTab === "mindmap" && (
                <div className="space-y-4">
                  <SectionHead title="Code Mind Map & AST Topology" />
                  <p className="text-xs font-mono text-[#8e8e9a] -mt-3 mb-3">
                    Interactive graph visualizing code structure, module dependencies, function call graphs, and risk findings.
                  </p>
                  <CodeMindMap data={mindMapData} />
                </div>
              )}

              {/* Overview */}
              {activeTab === "overview" && (
                <div className="space-y-5">
                  <SectionHead title="Security Overview" />
                  {/* Score cards */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {[
                      { label:"SECURITY SCORE", value:securityScore, suffix:"/100", color: securityScore>=80?"text-emerald-400":securityScore>=50?"text-amber-400":"text-red-400" },
                      { label:"ALIGNMENT",       value:alignmentScore, suffix:"/100", color:"text-[#ff5400]" },
                      { label:"QUANTUM READY",   value:quantumScore,   suffix:"/100", color:"text-amber-400" },
                      { label:"DEPENDENCIES",    value:depScore,       suffix:"/100", color:"text-emerald-400" },
                      { label:"OVERALL RISK",    value:overallRiskScore,suffix:"/100", color: overallRiskScore>60?"text-red-400":overallRiskScore>30?"text-amber-400":"text-emerald-400" },
                    ].map((c) => (
                      <div key={c.label} className="p-4 rounded-xl bg-[#12131a] border border-white/8 hover:border-[#ff5400]/20 transition-colors group">
                        <span className="text-[9px] font-mono text-[#8e8e9a] uppercase tracking-wider">{c.label}</span>
                        <div className={`text-2xl font-bold font-mono mt-1 ${c.color}`}>
                          {c.value}<span className="text-sm text-[#8e8e9a]">{c.suffix}</span>
                        </div>
                        {/* Mini progress bar */}
                        <div className="mt-2 h-0.5 rounded-full bg-white/8 overflow-hidden">
                          <div className={`h-full ${c.color.replace("text-","bg-")} rounded-full transition-all duration-700`} style={{ width:`${c.value}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Merge decision */}
                  <div className={`p-4 rounded-xl bg-[#12131a] border ${mergeDecision.border} flex items-center justify-between`}>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      <span className="text-[#8e8e9a]">MERGE DECISION</span>
                      <span className={`font-bold text-sm ${mergeDecision.color}`}>{mergeDecision.text}</span>
                    </div>
                    <span className="text-[10px] font-mono text-[#8e8e9a]">{mergeDecision.sub}</span>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">VULNERABLE SNIPPET PREVIEW</span>
                        {findings.length > 0 && (
                          <select
                            value={selectedFinding?.finding_id || ""}
                            onChange={(e) => { const f = findings.find((x:any) => (x.finding_id||x.id)===e.target.value); if(f) setSelectedFinding(f); }}
                            className="glass-input text-[10px] font-mono px-2 py-1 rounded cursor-pointer"
                          >
                            {findings.map((f:any) => <option key={f.finding_id||f.id} value={f.finding_id||f.id} className="bg-[#0c0d11]">{f.severity}: {f.category}</option>)}
                          </select>
                        )}
                      </div>
                      <VulnerabilityViewer
                        code={selectedFinding?.snippet || "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"}
                        language={selectedFinding?.file?.split(".").pop() || "python"}
                        filePath={selectedFinding?.file || "services/payment_service.py"}
                        vulnerableLine={selectedFinding?.line || 42}
                      />
                    </div>

                    <div className="bg-[#12131a] border border-white/8 p-5 rounded-xl">
                      <h3 className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider border-b border-white/8 pb-2 mb-3">UST ANALYSIS BREAKDOWN</h3>
                      {[
                        { label:"Languages Detected",      value:parsedLangs,                                                     color:"text-[#ff5400]" },
                        { label:"Total UST AST Nodes",     value:`${totalUstNodes.toLocaleString()} nodes`,                       color:"text-[#f4f4f8]" },
                        { label:"Vulnerabilities Found",   value:`${findings.length} findings`,                                   color:"text-red-400" },
                        { label:"Reachable & Exploitable", value:`${findings.filter((f:any)=>f.is_exploitable).length} items`,    color:"text-[#ff5400]" },
                        { label:"Deterministic Rules",     value:"100% verified",                                                 color:"text-emerald-400" },
                      ].map((r) => (
                        <div key={r.label} className="flex justify-between border-b border-white/8 py-2 text-xs font-mono last:border-0">
                          <span className="text-[#8e8e9a]">{r.label}</span>
                          <span className={`font-semibold ${r.color}`}>{r.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Security & Compliance */}
              {activeTab === "security_compliance" && (
                <div className="space-y-5">
                  <SectionHead title="Security Vulnerabilities" />

                  {/* Filters */}
                  <div className="flex flex-wrap gap-3 items-center justify-between bg-[#12131a] border border-white/8 p-4 rounded-xl">
                    <div className="flex items-center gap-3">
                      <input type="text" value={searchQuery} onChange={(e)=>setSearchQuery(e.target.value)} placeholder="Search category or file…" className="glass-input rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none w-52" />
                      <select value={severityFilter} onChange={(e)=>setSeverityFilter(e.target.value)} className="glass-input rounded-lg px-3 py-1.5 text-xs font-mono cursor-pointer">
                        {["All","Critical","High","Medium","Low"].map(s=><option key={s} value={s} className="bg-[#0c0d11]">{s}</option>)}
                      </select>
                    </div>
                    <span className="text-[9px] font-mono text-[#8e8e9a]">{filteredFindings.length} FINDING(S)</span>
                  </div>

                  {/* Findings table */}
                  <div className="overflow-x-auto rounded-xl bg-[#12131a] border border-white/8">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#0c0d11] text-[#8e8e9a] border-b border-white/8">
                        <tr>{["Severity","Category","CWE","Location","Reachable","Action"].map(h=><th key={h} className="p-3 text-[9px] uppercase tracking-wider font-semibold">{h}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {filteredFindings.map((f:any) => (
                          <tr key={f.finding_id||f.id} className="hover:bg-[#1a1b24] transition-colors">
                            <td className="p-3"><span className="px-2 py-0.5 rounded font-bold text-[9px] bg-[#ff5400]/10 text-[#ff5400] border border-[#ff5400]/20">{f.severity?.toUpperCase()}</span></td>
                            <td className="p-3 font-bold text-[#f4f4f8]">{f.category||f.title}</td>
                            <td className="p-3 text-[#8e8e9a]">{f.cwe||f.cwe_id||"—"}</td>
                            <td className="p-3 text-[#8e8e9a] truncate max-w-[160px]">{f.file}:{f.line||f.line_number}</td>
                            <td className="p-3">{f.is_exploitable?<span className="text-[#ff5400] font-semibold">Yes ({Math.round((f.exploitability_score||0)*100)}%)</span>:<span className="text-[#8e8e9a]">No</span>}</td>
                            <td className="p-3">
                              <button onClick={()=>{setSelectedFinding(f);setIsFindingDrawerOpen(true);}} className="px-3 py-1 rounded bg-[#ff5400]/10 hover:bg-[#ff5400]/20 text-[#ff5400] font-bold transition border border-[#ff5400]/20 text-[9px] hover:scale-105">INSPECT</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {[
                      { title:"BUSINESS INTENT & POLICY", content:<div className="p-3 rounded bg-[#0c0d11] border border-emerald-500/15"><div className="text-[9px] font-mono font-bold text-emerald-400 mb-1">[COMPLIANT] Manager Refund Approval Policy</div><p className="text-[10px] font-mono text-[#8e8e9a]">Requirement: "Refunds above 50,000 require manager authorization."</p></div> },
                      { title:"CRYPTOGRAPHIC BILL OF MATERIALS", content:<div className="overflow-x-auto rounded bg-[#0c0d11] border border-white/8"><table className="w-full text-[9px] font-mono"><thead className="border-b border-white/8 text-[#8e8e9a]"><tr><th className="p-2">Algo</th><th className="p-2">Status</th><th className="p-2">Count</th><th className="p-2">Target</th></tr></thead><tbody><tr><td className="p-2 font-bold text-[#f4f4f8]">MD5</td><td className="p-2 text-[#ff5400]">Broken</td><td className="p-2">2</td><td className="p-2 text-emerald-400">SHA-256</td></tr></tbody></table></div> },
                      { title:"DEPENDENCIES", content:<div className="p-3 rounded bg-[#0c0d11] border border-emerald-500/15 flex items-center justify-between"><span className="text-[10px] font-mono text-[#f4f4f8]">No vulnerable dependencies found.</span><CheckCircle className="w-4 h-4 text-emerald-500" /></div> },
                      { title:"IAC & RISK PROFILE", content:<div className="p-3 rounded bg-[#0c0d11] border border-white/8 space-y-1"><p className="text-[10px] font-mono text-[#8e8e9a]">IaC scans passed with <span className="text-emerald-400 font-bold">0 critical issues</span>.</p><p className="text-[10px] font-mono text-[#8e8e9a]">Overall risk: <span className="text-amber-400 font-bold">Moderate</span>.</p></div> },
                    ].map((panel) => (
                      <div key={panel.title} className="bg-[#12131a] border border-white/8 p-4 rounded-xl space-y-3">
                        <h3 className="text-[9px] font-mono font-bold uppercase tracking-wider text-[#f4f4f8]">{panel.title}</h3>
                        {panel.content}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* PR Review */}
              {activeTab === "pr_review" && (
                <div className="space-y-5">
                  <SectionHead title="PR Review & Integration" />
                  <div className="bg-[#12131a] border border-white/8 p-5 rounded-xl flex items-center justify-between">
                    <div>
                      <p className="text-xs font-mono text-[#8e8e9a] mt-0.5">Connect your repository to auto-generate pull requests for security fixes.</p>
                    </div>
                    <button className="px-4 py-2.5 glass-button rounded-lg font-mono text-[10px] font-bold tracking-wider transition flex items-center gap-2 shrink-0">
                      <GitPullRequest className="w-3.5 h-3.5" /> CONNECT GITHUB
                    </button>
                  </div>
                  <div className="space-y-3">
                    <h3 className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">SUGGESTED PULL REQUESTS</h3>
                    {[
                      { title:"Fix SQL Injection in Payment Service", desc:"Replaces string concatenation with parameterized queries.", file:"services/payment_service.py" },
                      { title:"Upgrade MD5 to SHA-256",               desc:"Migrates deprecated MD5 hashing to SHA-256.",             file:"utils/crypto.py" },
                    ].map((pr, i) => (
                      <div key={i} className="bg-[#12131a] border border-white/8 p-4 rounded-xl flex items-start justify-between group hover:border-[#ff5400]/20 transition-colors">
                        <div className="flex gap-3">
                          <div className="w-7 h-7 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20 mt-0.5 shrink-0">
                            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                          </div>
                          <div>
                            <h4 className="text-xs font-mono font-bold text-[#f4f4f8]">{pr.title}</h4>
                            <p className="text-[10px] font-mono text-[#8e8e9a] mt-1">{pr.desc}</p>
                            <div className="flex items-center gap-2 mt-2">
                              <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-[#0c0d11] border border-white/8 text-[#8e8e9a]">{pr.file}</span>
                              <span className="text-[9px] font-mono text-emerald-400 font-bold">+1</span>
                              <span className="text-[9px] font-mono text-red-400 font-bold">-1</span>
                            </div>
                          </div>
                        </div>
                        <button className="px-3 py-1.5 glass-button rounded-lg font-mono text-[9px] font-bold transition opacity-0 group-hover:opacity-100 shrink-0 ml-4">
                          CREATE PR
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Reports */}
              {activeTab === "reports" && (
                <div className="space-y-5">
                  <SectionHead title="Export Scan Reports" />
                  <div className="bg-[#12131a] border border-white/8 p-6 rounded-xl">
                    <p className="text-xs font-mono text-[#8e8e9a] mb-5">Download your security scan results in multiple industry-standard formats.</p>
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                      {[
                        { fmt:"json",  label:"JSON",   desc:"Raw data"     },
                        { fmt:"sarif", label:"SARIF",  desc:"IDE native"   },
                        { fmt:"html",  label:"HTML",   desc:"Web report"   },
                        { fmt:"csv",   label:"CSV",    desc:"Spreadsheet"  },
                        { fmt:"pdf",   label:"PDF",    desc:"Print-ready"  },
                      ].map(({ fmt, label, desc }) => (
                        <button
                          key={fmt}
                          onClick={() => handleDownloadReport(fmt)}
                          className="flex flex-col items-center justify-center gap-1.5 p-5 rounded-xl bg-[#0c0d11] border border-white/8 hover:border-[#ff5400]/30 hover:bg-[#ff5400]/5 group transition-all hover:scale-105"
                        >
                          <FileText className="w-5 h-5 text-[#8e8e9a] group-hover:text-[#ff5400] transition-colors" />
                          <span className="text-[11px] font-mono font-bold text-[#f4f4f8] group-hover:text-[#ff5400] transition-colors">.{label}</span>
                          <span className="text-[9px] font-mono text-[#8e8e9a]">{desc}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

            </PageTransition>
          </div>
        </main>
      </div>

      {/* Clean Floating AI Chatbot FAB */}
      <button
        onClick={() => setIsChatDrawerOpen(true)}
        className="fixed bottom-6 right-6 z-40 group flex items-center justify-center w-[52px] h-[52px] rounded-2xl bg-[#0f131f]/90 backdrop-blur-md border border-white/12 hover:border-[#ff5400]/60 text-[#f4f4f8] shadow-[0_4px_24px_rgba(0,0,0,0.4)] hover:shadow-[0_0_24px_rgba(255,84,0,0.35)] hover:scale-105 active:scale-95 transition-all duration-200"
        title="Chat with AI Security Assistant"
      >
        <Bot className="w-6 h-6 text-[#ff5400] group-hover:scale-110 transition-transform duration-200" />
        <span className="absolute top-2 right-2 w-2.5 h-2.5 bg-emerald-400 border-2 border-[#0B0F19] rounded-full" />
      </button>

      {/* Drawers */}
      <FindingDrawer finding={selectedFinding} isOpen={isFindingDrawerOpen} onClose={() => setIsFindingDrawerOpen(false)} onDiscussInChat={handleDiscussInChat} />
      <ChatDrawer    isOpen={isChatDrawerOpen}  onClose={() => setIsChatDrawerOpen(false)}  initialContext={chatContext} />
    </>
  );
}

/* ─── Root export wraps in Suspense for useSearchParams ─────────── */
export default function Home() {
  return (
    <Suspense>
      <AppInner />
    </Suspense>
  );
}
