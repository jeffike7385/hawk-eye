import { useEffect, useRef, useState } from "react";
import type { ProgressMessage } from "../types";

export function useWebSocket(scanId: string | undefined) {
  const [messages, setMessages] = useState<ProgressMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/scans/${scanId}/progress`);
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      const data: ProgressMessage = JSON.parse(event.data);
      setMessages((prev) => [...prev, data]);
    };
    return () => { ws.close(); wsRef.current = null; };
  }, [scanId]);

  const latest = messages.length > 0 ? messages[messages.length - 1] : null;
  return { messages, latest, connected };
}
