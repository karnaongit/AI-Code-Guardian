"use client";

import React from "react";
import { AlertTriangle, ShieldAlert, Zap, Flame } from "lucide-react";

export interface FunnelMetrics {
  total_alerts: number;
  exploitable_count: number;
  high_priority_count: number;
  immediate_risk_count: number;
}

interface TriageFunnelProps {
  metrics: FunnelMetrics;
  onFilterClick?: (filterType: string) => void;
}

export const TriageFunnel: React.FC<TriageFunnelProps> = ({ metrics, onFilterClick }) => {
  const funnelSteps = [
    {
      id: "total",
      label: "Total Scan Alerts",
      count: metrics.total_alerts,
      icon: AlertTriangle,
      color: "border-blue-500/30 bg-blue-500/10 text-blue-400",
      description: "Raw detections across static & UST engines",
    },
    {
      id: "exploitable",
      label: "Reachable & Exploitable",
      count: metrics.exploitable_count,
      icon: ShieldAlert,
      color: "border-amber-500/30 bg-amber-500/10 text-amber-400",
      description: "Confirmed taint flows reaching sinks",
    },
    {
      id: "high_priority",
      label: "High Priority",
      count: metrics.high_priority_count,
      icon: Zap,
      color: "border-orange-500/30 bg-orange-500/10 text-orange-400",
      description: "Critical & High severity findings",
    },
    {
      id: "immediate_risk",
      label: "Immediate Risk",
      count: metrics.immediate_risk_count,
      icon: Flame,
      color: "border-red-500/30 bg-red-500/10 text-red-400",
      description: "Reachable Critical/High vulnerabilities",
    },
  ];

  return (
    <div className="w-full my-4">
      <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
        Triage Funnel & Risk Prioritization
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {funnelSteps.map((step, index) => {
          const Icon = step.icon;
          return (
            <div
              key={step.id}
              onClick={() => onFilterClick && onFilterClick(step.id)}
              className={`relative flex flex-col justify-between p-4 rounded-xl border ${step.color} backdrop-blur-md cursor-pointer transition-all duration-200 hover:scale-[1.02] hover:shadow-lg`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">{step.label}</span>
                <Icon className="w-5 h-5 opacity-80" />
              </div>
              <div className="my-2">
                <span className="text-3xl font-extrabold tracking-tight">{step.count}</span>
              </div>
              <p className="text-[11px] text-slate-400 truncate">{step.description}</p>
              {index < funnelSteps.length - 1 && (
                <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-slate-600 text-sm">
                  ➔
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default TriageFunnel;
