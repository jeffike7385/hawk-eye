import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import type { ScanDetail as ScanDetailType } from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { ScanProgress } from "./ScanProgress";

export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (id) api.getScan(id).then(setScan).catch((e) => setError(String(e)));
  }, [id]);

  if (error) return (
    <div className="text-center py-12">
      <p className="text-red-400 mb-4">Scan not found</p>
      <a href="/" className="text-cyan-400 hover:underline">Back to Dashboard</a>
    </div>
  );

  if (!scan) return <p className="text-gray-400">Loading...</p>;

  const isActive = ["queued", "enumerating", "scanning"].includes(scan.status);
  if (isActive) {
    return <ScanProgress />;
  }

  const filtered = scan.findings.filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (search && !f.file_path.toLowerCase().includes(search.toLowerCase()) &&
        !f.pattern_name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">{scan.target_host}</h1>
          <p className="text-gray-500 text-sm">Scanned by {scan.entra_user} on {new Date(scan.created_at).toLocaleString()}</p>
        </div>
        <div className="flex gap-3 items-center">
          <StatusBadge status={scan.status} />
          <a href={`/api/scans/${scan.id}/report`} className="text-sm bg-cyan-600 hover:bg-cyan-500 text-white px-3 py-1 rounded">
            Download Report
          </a>
        </div>
      </div>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.findings.length}</div>
          <div className="text-gray-500 text-sm">Findings</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-red-400">{scan.findings.filter((f) => f.severity === "high").length}</div>
          <div className="text-gray-500 text-sm">High Severity</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.files_scanned}</div>
          <div className="text-gray-500 text-sm">Files Scanned</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.files_skipped}</div>
          <div className="text-gray-500 text-sm">Files Skipped</div>
        </div>
      </div>
      <div className="flex gap-3 mb-4">
        <input placeholder="Search files or patterns..." className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm flex-1"
          value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
          value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All Severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700 text-left">
            <th className="py-2">File</th><th>Pattern</th><th>Category</th><th>Severity</th><th>Matches</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((f) => (
            <tr key={f.id} className="border-b border-gray-800/50">
              <td className="py-2 max-w-xs truncate text-cyan-400" title={f.file_path}>{f.file_path}</td>
              <td>{f.pattern_name}</td>
              <td className="text-gray-400">{f.category}</td>
              <td>
                <span className={`font-medium ${f.severity === "high" ? "text-red-400" : f.severity === "medium" ? "text-amber-400" : "text-gray-400"}`}>
                  {f.severity}
                </span>
              </td>
              <td>{f.match_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
