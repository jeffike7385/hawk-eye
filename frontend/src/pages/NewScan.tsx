import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    target_host: "", username: "", password: "",
    transport: "" as string, paths: "C:\\Users",
    max_file_size_mb: 50, redact: true,
  });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const result = await api.createScan({
        ...form,
        transport: form.transport || null,
        paths: form.paths.split("\n").map((p) => p.trim()).filter(Boolean),
      });
      navigate(`/scans/${result.id}`);
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-6">New Scan</h1>
      {error && <div className="bg-red-900/50 text-red-300 p-3 rounded mb-4">{error}</div>}
      <label className="block text-sm text-gray-400 mb-1">Target Hostname</label>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.target_host} onChange={(e) => setForm({ ...form, target_host: e.target.value })} required />
      <label className="block text-sm text-gray-400 mb-1">Domain\Username</label>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
      <label className="block text-sm text-gray-400 mb-1">Password</label>
      <input type="password" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Transport</label>
          <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
            value={form.transport} onChange={(e) => setForm({ ...form, transport: e.target.value })}>
            <option value="">Auto-detect</option>
            <option value="smb">SMB</option>
            <option value="winrm">WinRM</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Max File Size (MB)</label>
          <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
            value={form.max_file_size_mb} onChange={(e) => setForm({ ...form, max_file_size_mb: Number(e.target.value) })} />
        </div>
      </div>
      <label className="block text-sm text-gray-400 mb-1">Scan Paths (one per line)</label>
      <textarea rows={3} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4 font-mono text-sm"
        value={form.paths} onChange={(e) => setForm({ ...form, paths: e.target.value })} />
      <label className="flex items-center gap-2 mb-6 text-sm">
        <input type="checkbox" checked={form.redact} onChange={(e) => setForm({ ...form, redact: e.target.checked })} />
        Redact matched values in report
      </label>
      <button type="submit" disabled={submitting}
        className="w-full bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-bold py-3 rounded disabled:opacity-50">
        {submitting ? "Starting..." : "Start Scan"}
      </button>
    </form>
  );
}
