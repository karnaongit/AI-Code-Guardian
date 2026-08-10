"use client";

import React from "react";
import { AlertTriangle, ShieldAlert, Zap, Flame, ArrowRight } from "lucide-react";

export interface FunnelMetrics {
  total_alerts: number;
  exploitable_count: number;
  high_priority_count: number;
  immediate_risk_count: number;
}

interface TriageFunnelProps {
  metrics: FunnelMetrics;
  onFilterClick?: (filterType: string) => void;
  compact?: boolean;
}

export const TriageFunnel: React.FC<TriageFunnelProps> = ({ metrics, onFilterClick }) => {
  const funnelSteps = [
    {
      id: "total",
      label: "TOTAL ALERTS",
      count: metrics.total_alerts,
      icon: AlertTriangle,
      badge: "bg-white/10 text-[#f4f4f8]",
      iconColor: "text-[#8e8e9a]",
    },
    {
      id: "exploitable",
      label: "EXPLOITABLE",
      count: metrics.exploitable_count,
      icon: ShieldAlert,
      badge: "bg-[#ff5400]/15 text-[#ff5400] border border-[#ff5400]/30",
      iconColor: "text-[#ff5400]",
    },
    {
      id: "high_priority",
      label: "HIGH PRIORITY",
      count: metrics.high_priority_count,
      icon: Zap,
      badge: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
      iconColor: "text-orange-400",
    },
    {
      id: "immediate_risk",
      label: "IMMEDIATE RISK",
      count: metrics.immediate_risk_count,
      icon: Flame,
      badge: "bg-red-500/15 text-red-400 border border-red-500/30",
      iconColor: "text-red-400",
    },
  ];

  return (
    <div className="w-full bg-[#12131a] border border-white/8 rounded-xl px-4 py-2 flex flex-wrap items-center justify-between gap-3 shrink-0 shadow-sm">
      {/* Title */}
      <div className="flex items-center gap-2 text-[10px] font-mono font-bold tracking-widest text-[#8e8e9a]">
        <span className="w-2 h-2 rounded-full bg-[#ff5400] animate-pulse shrink-0" />
        <span className="text-[#f4f4f8]">TRIAGE FUNNEL & RISK PRIORITIZATION</span>
      </div>

      {/* Metrics Row (Single Line) */}
      <div className="flex items-center gap-2 sm:gap-3 overflow-x-auto py-0.5">
        {funnelSteps.map((step, index) => {
          const Icon = step.icon;
          return (
            <React.Fragment key={step.id}>
              <button
                onClick={() => onFilterClick && onFilterClick(step.id)}
                className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-white/4 hover:bg-white/8 border border-white/6 transition-all duration-150 group cursor-pointer shrink-0"
              >
                <Icon className={`w-3.5 h-3.5 ${step.iconColor} shrink-0`} />
                <span className="text-[10px] font-mono font-medium text-[#8e8e9a] group-hover:text-[#f4f4f8] transition-colors">
                  {step.label}
                </span>
                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded ${step.badge}`}>
                  {step.count}
                </span>
              </button>
              {index < funnelSteps.length - 1 && (
                <ArrowRight className="w-3 h-3 text-[#8e8e9a]/40 shrink-0 hidden sm:block" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

export default TriageFunnel;

