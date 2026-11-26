"use client";

import React, { useCallback, useState } from "react";
import { useAuth } from "@/components/AuthContext";
import { useSharedStream } from "@/components/StreamContext";
import { TrafficInspector } from "@/components/TrafficInspector";
import { clearAllLogs } from "@/lib/api";

export default function LogsPage() {
  const { user } = useAuth();
  const { logs, tunnels, sseState, clearLogsLocal } = useSharedStream();
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === "admin";

  const handleClearLogs = useCallback(async () => {
    setError(null);
    try {
      await clearAllLogs();
      clearLogsLocal();
    } catch (err) {
      setError(err instanceof Error ? err.message : "清空日志失败");
    }
  }, [clearLogsLocal]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          流量日志
        </h1>
        <p className="mt-1 text-xs text-secondary">
          实时观察通过泛域名与路径代理转发的 HTTP 及 WebSocket 请求。点击任意行可展开请求详情。
        </p>
      </div>

      {error ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2.5 text-xs text-red-600 dark:text-red-400"
        >
          {error}
        </div>
      ) : null}

      <TrafficInspector
        logs={logs}
        tunnels={tunnels}
        sseState={sseState}
        canClear={isAdmin}
        onClearLogs={isAdmin ? handleClearLogs : undefined}
      />
    </div>
  );
}
