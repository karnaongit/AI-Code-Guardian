"use client";

import React, { useState } from "react";
import { X, Send, Bot, User, Sparkles, Shield, Terminal, Briefcase } from "lucide-react";

export type PersonaType = "Executive" | "Developer" | "Red Teamer";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  persona?: PersonaType;
  toolsUsed?: string[];
}

interface ChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  initialContext?: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const ChatDrawer: React.FC<ChatDrawerProps> = ({
  isOpen,
  onClose,
  initialContext = "",
}) => {
  const [persona, setPersona] = useState<PersonaType>("Developer");
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "1",
      role: "assistant",
      content: `Hello! I am your AI Code Guardian Assistant tailored for the **${persona}** persona. How can I assist you with security findings or code analysis today?`,
      persona: persona,
    },
  ]);
  const [input, setInput] = useState(initialContext ? `Tell me more about finding: ${initialContext}` : "");
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      persona: persona,
    };

    setMessages((prev) => [...prev, userMsg]);
    const currentInput = input;
    setInput("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: [{ role: "user", content: currentInput }],
          persona: persona,
          temperature: 0.2,
        }),
      });

      if (!response.ok) throw new Error("Chat request failed");
      const data = await response.json();

      const assistantMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.reply || "Analysis completed.",
        persona: data.persona || persona,
        toolsUsed: data.tools_used || [],
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: "assistant",
          content: "Sorry, an error occurred while connecting to the AI reasoning service.",
          persona: persona,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const getPersonaIcon = (p: PersonaType) => {
    if (p === "Executive") return <Briefcase className="w-4 h-4 text-blue-400" />;
    if (p === "Developer") return <Terminal className="w-4 h-4 text-emerald-400" />;
    return <Shield className="w-4 h-4 text-red-400" />;
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/40 backdrop-blur-md flex justify-end">
      <div className="w-full max-w-xl glass-panel border-l border-white/10 text-slate-100 h-full flex flex-col shadow-[[-20px_0_40px_rgba(0,0,0,0.3)]] animate-in slide-in-from-right duration-300">
        
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600">
              <Bot className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                AI Guardian Chat <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              </h2>
              <p className="text-[11px] text-slate-400">Contextual Reasoning & Persona Guidance</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Persona Dropdown Selector */}
            <div className="flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-lg px-2 py-1">
              {getPersonaIcon(persona)}
              <select
                value={persona}
                onChange={(e) => setPersona(e.target.value as PersonaType)}
                className="bg-transparent text-xs font-semibold text-slate-200 focus:outline-none cursor-pointer"
              >
                <option value="Executive" className="bg-slate-900 text-slate-200">Executive</option>
                <option value="Developer" className="bg-slate-900 text-slate-200">Developer</option>
                <option value="Red Teamer" className="bg-slate-900 text-slate-200">Red Teamer</option>
              </select>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Message Thread */}
        <div className="p-4 flex-1 overflow-y-auto space-y-4">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {msg.role === "assistant" && (
                <div className="w-8 h-8 rounded-full glass-card flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4 text-blue-400" />
                </div>
              )}
              <div
                className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed space-y-2 ${
                  msg.role === "user"
                    ? "bg-gradient-to-br from-blue-600/90 to-blue-500/90 text-white rounded-tr-none shadow-lg backdrop-blur-md"
                    : "glass-card text-slate-200 rounded-tl-none"
                }`}
              >
                {msg.persona && msg.role === "assistant" && (
                  <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1.5 mb-1 text-[10px] text-slate-400">
                    <span className="font-semibold text-slate-300 flex items-center gap-1">
                      {getPersonaIcon(msg.persona)} {msg.persona} Mode
                    </span>
                    {msg.toolsUsed && msg.toolsUsed.length > 0 && (
                      <span className="text-amber-400/90 font-mono text-[9px]">
                        Tools: {msg.toolsUsed.join(", ")}
                      </span>
                    )}
                  </div>
                )}
                <div className="whitespace-pre-wrap">{msg.content}</div>
              </div>
              {msg.role === "user" && (
                <div className="w-8 h-8 rounded-full bg-blue-600/20 border border-blue-500/40 flex items-center justify-center shrink-0">
                  <User className="w-4 h-4 text-blue-400" />
                </div>
              )}
            </div>
          ))}
          {loading && (
            <div className="flex gap-3 justify-start items-center text-xs text-slate-400 font-mono animate-pulse">
              <Bot className="w-4 h-4 text-blue-400" />
              <span>Nemotron reasoning in progress...</span>
            </div>
          )}
        </div>

        {/* Input Footer */}
        <form onSubmit={handleSendMessage} className="p-4 border-t border-white/10 glass-panel flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`Ask in ${persona} persona...`}
            className="flex-1 glass-input rounded-xl px-4 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500/50 transition"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="p-2.5 rounded-xl glass-button text-white disabled:opacity-50 transition"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

      </div>
    </div>
  );
};

export default ChatDrawer;
