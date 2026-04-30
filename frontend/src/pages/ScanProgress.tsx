import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { useWebSocket } from "../hooks/useWebSocket";
import { ProgressBar } from "../components/ProgressBar";
import { StatusBadge } from "../components/StatusBadge";
import type { ScanDetail } from "../types";

export function ScanProgress() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const { latest, messages } = useWebSocket(id);

  useEffect(() => {
    if (id) api.getScan(id).then(setScan);
  }, [id]);

  useEffect(() => {
    if (latest?.phase === "completed" || latest?.phase === "failed") {
      if (id) api.getScan(id).then(setScan);
    }
  }, [latest, id]);

  if (!scan) return <p className="text-gray-400">Loading...</p>;

  const isActive = ["queued", "enumerating", "scanning"].includes(scan.status);
  const phase = latest?.phase || scan.status;
  const current = latest?.current || 0;
  const total = latest?.total || scan.files_found || 0;

  if (!isActive) {
    return (
      <div>
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold">{scan.target_host}</h1>
            <p className="text-gray-500 text-sm">Scan {scan.status}</p>
          </div>
          <StatusBadge status={scan.status} />
        </div>
        {scan.status === "completed" && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-gray-900 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold">{scan.findings.length}</div>
                <div className="text-gray-500 text-sm">Findings</div>
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
            <Link to={`/scans/${id}`} className="text-cyan-400 hover:underline">View full details</Link>
          </div>
        )}
        {scan.error_message && (
          <div className="bg-red-900/30 border border-red-800 rounded p-4 mt-4">
            <p className="text-red-300">{scan.error_message}</p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scanning {scan.target_host}</h1>
          <p className="text-gray-500 text-sm">Started by {scan.entra_user}</p>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Status</div>
          <div className="font-bold capitalize">{phase}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Progress</div>
          <div className="font-bold">{current} / {total} files</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Findings</div>
          <div className="font-bold">{latest?.findings_count ?? "—"}</div>
        </div>
      </div>
      <ProgressBar current={current} total={total} />
      <div className="mt-6">
        <h2 className="font-bold mb-2">Live Activity</h2>
        <div className="bg-gray-900 rounded-lg p-4 font-mono text-xs max-h-60 overflow-y-auto space-y-1">
          {messages.slice(-20).map((msg, i) => (
            <div key={i} className="text-gray-400">
              {msg.phase === "scanning" && msg.filename && `Scanning ${msg.filename}...`}
              {msg.phase === "enumerating" && `Enumerating... ${msg.files_found} files found`}
              {msg.phase === "completed" && <span className="text-green-400">Scan complete</span>}
              {msg.phase === "failed" && <span className="text-red-400">Failed: {msg.error}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
