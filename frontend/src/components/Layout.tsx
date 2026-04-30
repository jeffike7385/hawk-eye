import { Link, Outlet } from "react-router-dom";
import { api } from "../api";
import type { UserInfo } from "../types";

export function Layout({ user }: { user: UserInfo }) {
  const handleLogout = async () => {
    await api.logout();
    window.location.href = "/api/auth/login";
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex justify-between items-center">
        <div className="flex items-center gap-6">
          <Link to="/" className="text-lg font-bold text-cyan-400">Hawk Scan</Link>
          <Link to="/" className="text-sm text-gray-400 hover:text-gray-200">Dashboard</Link>
          <Link to="/scans/new" className="text-sm text-gray-400 hover:text-gray-200">New Scan</Link>
          <Link to="/scans" className="text-sm text-gray-400 hover:text-gray-200">History</Link>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-gray-400">{user.email}</span>
          <button onClick={handleLogout} className="text-gray-500 hover:text-gray-300">Logout</button>
        </div>
      </nav>
      <main className="p-6 max-w-7xl mx-auto"><Outlet /></main>
    </div>
  );
}
