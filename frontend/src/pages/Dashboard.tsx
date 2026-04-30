import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { ScanSummary } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getScans(1).then((data) => { setScans(data.items); setLoading(false); });
  }, []);

  const active = scans.filter((s) => ["queued", "enumerating", "scanning"].includes(s.status));
  const totalFindings = scans.reduce((acc, s) => acc + s.high_count + s.medium_count + s.low_count, 0);
  const highFindings = scans.reduce((acc, s) => acc + s.high_count, 0);

  if (loading) return <p className="text-gray-400">Loading...</p>;

  return (
    <div>
      <div className="grid grid-cols-4 gap-4 mb-8">
        {[
          { label: "Total Scans", value: scans.length, color: "text-cyan-400" },
          { label: "Running Now", value: active.length, color: "text-green-400" },
          { label: "Total Findings", value: totalFindings, color: "text-orange-400" },
          { label: "High Severity", value: highFindings, color: "text-red-400" },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-gray-500 text-sm">{stat.label}</div>
          </div>
        ))}
      </div>
      <h2 className="text-lg font-bold mb-3">Recent Scans</h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            <th className="text-left py-2">Target</th>
            <th className="text-left">Status</th>
            <th className="text-left">Findings</th>
            <th className="text-left">Date</th>
            <th className="text-left">By</th>
          </tr>
        </thead>
        <tbody>
          {scans.slice(0, 10).map((scan) => (
            <tr key={scan.id} className="border-b border-gray-800/50">
              <td className="py-2"><Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline">{scan.target_host}</Link></td>
              <td><StatusBadge status={scan.status} /></td>
              <td>
                {scan.high_count > 0 && <span className="text-red-400">{scan.high_count} high</span>}
                {scan.high_count > 0 && scan.medium_count > 0 && " · "}
                {scan.medium_count > 0 && <span>{scan.medium_count} med</span>}
              </td>
              <td className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
              <td className="text-gray-500">{scan.entra_user}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
