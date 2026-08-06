import { useState, useEffect } from 'react';
import type { SeverityAnalytics, TrendAnalytics } from '../api/client';
import { apiClient } from '../api/client';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Activity } from 'lucide-react';

export default function AnalyticsDashboard() {
  const [sevData, setSevData] = useState<SeverityAnalytics | null>(null);
  const [trendData, setTrendData] = useState<TrendAnalytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [sev, trends] = await Promise.all([
        apiClient.getSeverityAnalytics(),
        apiClient.getTrendAnalytics()
      ]);
      setSevData(sev);
      setTrendData(trends);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  // Transform severity dict to array for Recharts
  const chartData = sevData ? Object.entries(sevData.by_severity).map(([name, count]) => ({ name, count })) : [];

  return (
    <div className="p-6 h-full overflow-y-auto bg-slate-900 text-slate-200">
      <div className="mb-8 flex items-center gap-2">
        <Activity className="text-blue-500" size={28} />
        <h2 className="text-2xl font-bold">Analytics & Metrics</h2>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
            <h3 className="text-lg font-semibold mb-6 text-slate-300 uppercase tracking-wide">Findings by Severity</h3>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                    itemStyle={{ color: '#3b82f6' }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
            <h3 className="text-lg font-semibold mb-6 text-slate-300 uppercase tracking-wide">Score Trend over Time</h3>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData?.trends || []} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="timestamp" stroke="#94a3b8" tickFormatter={(v: any) => new Date(v).toLocaleDateString()} />
                  <YAxis stroke="#94a3b8" domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                    labelFormatter={(v: any) => new Date(v).toLocaleString()}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="security_score" stroke="#10b981" strokeWidth={3} activeDot={{ r: 8 }} />
                  <Line type="monotone" dataKey="risk_score" stroke="#ef4444" strokeWidth={3} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
