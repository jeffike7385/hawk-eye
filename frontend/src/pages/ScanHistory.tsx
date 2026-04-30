import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { ScanSummary } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function ScanHistory() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");

  useEffect(() => {
    api.getScans(page, statusFilter || undefined, targetFilter || undefined).then((data) => {
      setScans(data.items);
      setTotal(data.total);
    });
  }, [page, statusFilter, targetFilter]);

  const totalPages = Math.ceil(total / 20);

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Scan History</h1>
        <div className="flex gap-3">
          <input placeholder="Search targets..." className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
            value={targetFilter} onChange={(e) => { setTargetFilter(e.target.value); setPage(1); }} />
          <select className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
            value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
            <option value="">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="scanning">Scanning</option>
            <option value="failed">Failed</option>
            <option value="queued">Queued</option>
          </select>
        </div>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700 text-left">
            <th className="py-2">Target</th><th>Status</th><th>Findings</th>
            <th>High</th><th>Scanned By</th><th>Date</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className="border-b border-gray-800/50">
              <td className="py-2"><Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline">{scan.target_host}</Link></td>
              <td><StatusBadge status={scan.status} /></td>
              <td>{scan.high_count + scan.medium_count + scan.low_count || "—"}</td>
              <td className={scan.high_count > 0 ? "text-red-400 font-bold" : "text-green-400"}>{scan.high_count}</td>
              <td className="text-gray-500">{scan.entra_user}</td>
              <td className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
              <td><Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline text-xs">View</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex justify-between items-center mt-4 text-sm text-gray-500">
        <span>Showing {scans.length} of {total} scans</span>
        <div className="flex gap-2">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30">Prev</button>
          <span className="px-3 py-1">{page} / {totalPages || 1}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30">Next</button>
        </div>
      </div>
    </div>
  );
}
