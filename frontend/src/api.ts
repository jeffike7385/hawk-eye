const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (resp.status === 401) {
    window.location.href = "/api/auth/login";
    throw new Error("Not authenticated");
  }
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${resp.status}: ${text}`);
  }
  if (resp.status === 204) return undefined as T;
  return resp.json();
}

export const api = {
  getMe: () => request<{ email: string; name: string }>("/auth/me"),
  getScans: (page = 1, status?: string, target?: string) => {
    const params = new URLSearchParams({ page: String(page) });
    if (status) params.set("status", status);
    if (target) params.set("target", target);
    return request<import("./types").ScanListResponse>(`/scans?${params}`);
  },
  getScan: (id: string) => request<import("./types").ScanDetail>(`/scans/${id}`),
  createScan: (body: Record<string, unknown>) =>
    request<import("./types").ScanDetail>("/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteScan: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
};
