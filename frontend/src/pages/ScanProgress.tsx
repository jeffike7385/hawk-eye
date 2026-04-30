import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { ProgressBar } from "../components/ProgressBar";
import { StatusBadge } from "../components/StatusBadge";
import type { ScanDetail } from "../types";

export function ScanProgress() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    let active = true;

    const poll = () => {
      api.getScan(id)
        .then((data) => {
          if (!active) return;
          setScan(data);
          if (["queued", "enumerating", "scanning"].includes(data.status)) {
            setTimeout(poll, 3000);
          }
        })
        .catch((e) => { if (active) setError(String(e)); });
    };
    poll();

    return () => { active = false; };
  }, [id]);

  if (error) return (
    <div className="text-center py-12">
      <p className="text-red-400 mb-4">Failed to load scan</p>
      <a href="/" className="text-cyan-400 hover:underline">Back to Dashboard</a>
    </div>
  );

  if (!scan) return <p className="text-gray-400">Loading...</p>;

  const isActive = ["queued", "enumerating", "scanning"].includes(scan.status);
  const current = scan.files_scanned || 0;
  const total = scan.files_found || 0;

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
        <StatusBadge status={scan.status} />
      </div>
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Status</div>
          <div className="font-bold capitalize">{scan.status}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Progress</div>
          <div className="font-bold">{current} / {total} files</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Files Found</div>
          <div className="font-bold">{scan.files_found ?? "—"}</div>
        </div>
      </div>
      {total > 0 && <ProgressBar current={current} total={total} />}
      <div className="mt-6 bg-gray-900 rounded-lg p-4 text-sm text-gray-400">
        <p>Polling for updates every 3 seconds...</p>
        {scan.status === "enumerating" && <p className="mt-2">Enumerating remote files. This can take several minutes for large directory trees.</p>}
        {scan.status === "scanning" && <p className="mt-2">Scanning {current} of {total} files for PII patterns.</p>}
      </div>
    </div>
  );
}
