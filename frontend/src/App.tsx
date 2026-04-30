import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { api } from "./api";
import type { UserInfo } from "./types";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanHistory } from "./pages/ScanHistory";
import { ScanDetail } from "./pages/ScanDetail";

export default function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getMe().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }

  if (!user) {
    window.location.href = "/api/auth/login";
    return null;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout user={user} />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/scans" element={<ScanHistory />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
