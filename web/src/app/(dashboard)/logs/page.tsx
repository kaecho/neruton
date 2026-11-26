"use client";

import React, { useCallback, useState } from "react";
import { useAuth } from "@/components/AuthContext";
import { useSharedStream } from "@/components/StreamContext";
import { TrafficInspector } from "@/components/TrafficInspector";
import { clearAllLogs } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

export default function LogsPage() {
  const { messages } = useI18n();
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
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.logs.clearFailed,
      );
    }
  }, [clearLogsLocal, messages.logs.clearFailed]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          {messages.logs.title}
        </h1>
        <p className="mt-1 text-xs text-secondary">{messages.logs.subtitle}</p>
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
