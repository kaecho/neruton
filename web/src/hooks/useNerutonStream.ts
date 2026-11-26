"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchLogs, fetchServerInfo, fetchTunnels } from "@/lib/api";
import type {
  RequestLog,
  ServerInfo,
  SseConnectionState,
  TunnelInfo,
} from "@/lib/types";

const MAX_LOGS = 200;
const POLL_INTERVAL_MS = 3000;
const SSE_RECONNECT_MS = 12000;
const CONNECTED_SYNC_MS = 10000;

interface UseNerutonStreamOptions {
  /** Optional prefix filter when used inside /preview/[prefix] */
  prefixFilter?: string;
}

export interface UseNerutonStreamResult {
  info: ServerInfo | null;
  tunnels: TunnelInfo[];
  logs: RequestLog[];
  sseState: SseConnectionState;
  isLoading: boolean;
  error: string | null;
  lastUpdatedAt: number | null;
  refresh: () => Promise<void>;
}

function isTunnelInfo(obj: unknown): obj is TunnelInfo {
  return (
    typeof obj === "object" &&
    obj !== null &&
    typeof (obj as TunnelInfo).prefix === "string" &&
    typeof (obj as TunnelInfo).target_url === "string"
  );
}

function isRequestLog(obj: unknown): obj is RequestLog {
  return (
    typeof obj === "object" &&
    obj !== null &&
    typeof (obj as RequestLog).tunnel_prefix === "string" &&
    typeof (obj as RequestLog).method === "string" &&
    typeof (obj as RequestLog).path === "string"
  );
}

function extractRecord(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === "object" && raw !== null) {
    return raw as Record<string, unknown>;
  }
  return null;
}

function mergeLogs(existing: RequestLog[], incoming: RequestLog[]): RequestLog[] {
  const byId = new Map<string, RequestLog>();
  for (const log of incoming) {
    byId.set(log.id || `${log.timestamp}-${log.tunnel_prefix}-${log.path}-${Math.random()}`, log);
  }
  for (const log of existing) {
    const key = log.id || `${log.timestamp}-${log.tunnel_prefix}-${log.path}`;
    if (!byId.has(key)) {
      byId.set(key, log);
    }
  }
  return Array.from(byId.values())
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, MAX_LOGS);
}

export function useNerutonStream(
  options: UseNerutonStreamOptions = {},
): UseNerutonStreamResult {
  const { prefixFilter } = options;

  const [info, setInfo] = useState<ServerInfo | null>(null);
  const [tunnels, setTunnels] = useState<TunnelInfo[]>([]);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [sseState, setSseState] = useState<SseConnectionState>("connecting");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);

  const mountedRef = useRef(true);
  const syncTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [nextInfo, nextTunnels, nextLogs] = await Promise.all([
        fetchServerInfo(),
        fetchTunnels(),
        fetchLogs(prefixFilter),
      ]);
      if (!mountedRef.current) return;
      setInfo(nextInfo);
      setTunnels(nextTunnels);
      setLogs(
        [...nextLogs]
          .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
          .slice(0, MAX_LOGS),
      );
      setError(null);
      setLastUpdatedAt(Date.now());
    } catch (err) {
      if (!mountedRef.current) return;
      const message = err instanceof Error ? err.message : "无法连接到 Neruton 网关";
      setError(message);
    } finally {
      if (mountedRef.current) {
        setIsLoading(false);
      }
    }
  }, [prefixFilter]);

  const scheduleLightSync = useCallback(() => {
    if (syncTimerRef.current) return;
    syncTimerRef.current = setTimeout(() => {
      syncTimerRef.current = null;
      if (mountedRef.current) {
        void refresh();
      }
    }, 600);
  }, [refresh]);

  useEffect(() => {
    mountedRef.current = true;
    void refresh();

    let eventSource: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let connectedSyncTimer: ReturnType<typeof setInterval> | null = null;

    const clearPolling = () => {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const startPolling = () => {
      if (pollTimer) return;
      pollTimer = setInterval(() => {
        if (mountedRef.current) {
          void refresh();
        }
      }, POLL_INTERVAL_MS);
    };

    const handleParsedEvent = (eventType: string, payload: unknown) => {
      if (!mountedRef.current) return;
      const rec = extractRecord(payload);
      const resolvedType =
        eventType && eventType !== "message"
          ? eventType
          : typeof rec?.type === "string"
            ? rec.type
            : typeof rec?.event === "string"
              ? rec.event
              : "";

      const inner = rec?.data ?? rec?.payload ?? rec?.tunnel ?? rec?.log ?? payload;

      if (resolvedType === "tunnel_connected") {
        const candidate = isTunnelInfo(inner) ? inner : isTunnelInfo(rec) ? rec : null;
        if (candidate) {
          setTunnels((prev) => {
            const exists = prev.some((t) => t.prefix === candidate.prefix);
            const next = exists
              ? prev.map((t) => (t.prefix === candidate.prefix ? candidate : t))
              : [candidate, ...prev];
            return next;
          });
          setLastUpdatedAt(Date.now());
        }
        scheduleLightSync();
        return;
      }

      if (resolvedType === "tunnel_disconnected") {
        const prefix =
          (typeof rec?.prefix === "string" && rec.prefix) ||
          (typeof (extractRecord(inner)?.prefix) === "string" &&
            (extractRecord(inner)?.prefix as string)) ||
          null;
        const id =
          (typeof rec?.id === "string" && rec.id) ||
          (typeof rec?.tunnel_id === "string" && rec.tunnel_id) ||
          null;

        if (prefix || id) {
          setTunnels((prev) =>
            prev.filter((t) => (prefix ? t.prefix !== prefix : true) && (id ? t.id !== id : true)),
          );
          setLastUpdatedAt(Date.now());
        }
        scheduleLightSync();
        return;
      }

      if (resolvedType === "request_logged") {
        const candidate = isRequestLog(inner) ? inner : isRequestLog(rec) ? rec : null;
        if (candidate) {
          if (!prefixFilter || candidate.tunnel_prefix === prefixFilter) {
            setLogs((prev) => mergeLogs(prev, [candidate]));
          }
          setInfo((prev) =>
            prev ? { ...prev, total_requests: prev.total_requests + 1 } : prev,
          );
          setTunnels((prev) =>
            prev.map((t) =>
              t.prefix === candidate.tunnel_prefix
                ? {
                    ...t,
                    requests_total: t.requests_total + 1,
                    bytes_in: t.bytes_in + (candidate.bytes_in || 0),
                    bytes_out: t.bytes_out + (candidate.bytes_out || 0),
                  }
                : t,
            ),
          );
          setLastUpdatedAt(Date.now());
        } else {
          scheduleLightSync();
        }
        return;
      }

      if (resolvedType === "heartbeat") {
        setSseState("connected");
        setLastUpdatedAt(Date.now());
        if (rec) {
          const hbActive =
            typeof rec.active_tunnels === "number" ? rec.active_tunnels : undefined;
          const hbTotal =
            typeof rec.total_requests === "number" ? rec.total_requests : undefined;
          if (hbActive !== undefined || hbTotal !== undefined) {
            setInfo((prev) =>
              prev
                ? {
                    ...prev,
                    active_tunnels: hbActive ?? prev.active_tunnels,
                    total_requests: hbTotal ?? prev.total_requests,
                  }
                : prev,
            );
          }
        }
        return;
      }

      // Unknown shape: perform a gentle refresh
      scheduleLightSync();
    };

    const parseAndDispatch = (eventType: string, rawData: string) => {
      if (!rawData) return;
      try {
        const parsed = JSON.parse(rawData);
        handleParsedEvent(eventType, parsed);
      } catch {
        if (eventType === "heartbeat") {
          setSseState("connected");
        }
      }
    };

    const connectSse = () => {
      if (!mountedRef.current || typeof EventSource === "undefined") {
        setSseState("polling");
        startPolling();
        return;
      }

      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }

      try {
        const es = new EventSource("/_neruton/api/events");
        eventSource = es;

        es.onopen = () => {
          if (!mountedRef.current) return;
          setSseState("connected");
          setError(null);
          clearPolling();
          if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
          }
        };

        es.onmessage = (ev) => {
          parseAndDispatch("message", ev.data);
        };

        const namedEvents = [
          "tunnel_connected",
          "tunnel_disconnected",
          "request_logged",
          "heartbeat",
        ] as const;

        for (const name of namedEvents) {
          es.addEventListener(name, (ev) => {
            const msg = ev as MessageEvent<string>;
            parseAndDispatch(name, msg.data);
          });
        }

        es.onerror = () => {
          if (!mountedRef.current) return;
          es.close();
          eventSource = null;
          setSseState("polling");
          startPolling();

          if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => {
              reconnectTimer = null;
              connectSse();
            }, SSE_RECONNECT_MS);
          }
        };
      } catch {
        setSseState("polling");
        startPolling();
      }
    };

    connectSse();

    connectedSyncTimer = setInterval(() => {
      if (mountedRef.current) {
        void refresh();
      }
    }, CONNECTED_SYNC_MS);

    return () => {
      mountedRef.current = false;
      if (eventSource) eventSource.close();
      clearPolling();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (connectedSyncTimer) clearInterval(connectedSyncTimer);
      if (syncTimerRef.current) clearTimeout(syncTimerRef.current);
    };
  }, [prefixFilter, refresh, scheduleLightSync]);

  return {
    info,
    tunnels,
    logs,
    sseState,
    isLoading,
    error,
    lastUpdatedAt,
    refresh,
  };
}
