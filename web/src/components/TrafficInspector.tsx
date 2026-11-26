"use client";

import React, { memo, useDeferredValue, useMemo, useState } from "react";
import Link from "next/link";
import {
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Pause,
  Play,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { StatusDot } from "@/components/GeistPrimitives";
import {
  formatBytes,
  formatClockTime,
  formatDurationMs,
} from "@/lib/format";
import type {
  RequestLog,
  SseConnectionState,
  TunnelInfo,
} from "@/lib/types";

interface TrafficInspectorProps {
  logs: RequestLog[];
  tunnels?: TunnelInfo[];
  sseState?: SseConnectionState;
  compact?: boolean;
  lockedPrefix?: string;
  onNavigatePath?: (path: string) => void;
  canClear?: boolean;
  onClearLogs?: () => Promise<void>;
}

const HTTP_METHODS = [
  "ALL",
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "WS",
] as const;

function getStatusColor(status: number): string {
  if (status === 101) return "text-blue-600 dark:text-blue-400";
  if (status >= 200 && status < 300) return "text-emerald-600 dark:text-emerald-400";
  if (status >= 300 && status < 400) return "text-blue-600 dark:text-blue-400";
  if (status >= 400 && status < 500) return "text-amber-600 dark:text-amber-400";
  if (status >= 500) return "text-red-600 dark:text-red-400";
  return "text-secondary";
}

interface LogRowProps {
  log: RequestLog;
  isExpanded: boolean;
  lockedPrefix?: string;
  onToggle: (rowKey: string) => void;
  rowKey: string;
  onNavigatePath?: (path: string) => void;
}

const LogRow = memo(function LogRow({
  log,
  isExpanded,
  lockedPrefix,
  onToggle,
  rowKey,
  onNavigatePath,
}: LogRowProps) {
  const totalSize = (log.bytes_in || 0) + (log.bytes_out || 0);
  const directPath = `/t/${encodeURIComponent(log.tunnel_prefix)}${log.path.startsWith("/") ? log.path : `/${log.path}`}`;

  return (
    <>
      <tr
        onClick={() => onToggle(rowKey)}
        className={`log-row cursor-pointer transition-colors hover:bg-surface ${
          isExpanded ? "bg-surface" : ""
        }`}
      >
        <td className="w-7 py-2 pl-3 pr-1 text-tertiary">
          {isExpanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </td>
        <td className="whitespace-nowrap px-2.5 py-2 font-mono text-[11px] tabular-nums text-secondary">
          {formatClockTime(log.timestamp)}
        </td>
        <td className="whitespace-nowrap px-2.5 py-2">
          <span className="inline-block rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground">
            {log.method}
          </span>
        </td>
        <td
          className={`whitespace-nowrap px-2.5 py-2 font-mono text-xs font-medium tabular-nums ${getStatusColor(log.status)}`}
        >
          {log.status}
        </td>
        {!lockedPrefix ? (
          <td className="whitespace-nowrap px-2.5 py-2">
            <Link
              href={`/preview/${encodeURIComponent(log.tunnel_prefix)}`}
              onClick={(e) => e.stopPropagation()}
              className="inline-block max-w-[140px] truncate font-mono text-[11px] text-foreground underline-offset-4 hover:underline"
              title={log.tunnel_prefix}
            >
              {log.tunnel_prefix}
            </Link>
          </td>
        ) : null}
        <td className="whitespace-nowrap px-2.5 py-2 text-[11px] text-secondary">
          {log.via === "path" ? "路径代理" : "泛域名"}
        </td>
        <td
          className="max-w-[340px] truncate px-2.5 py-2 font-mono text-xs text-foreground"
          title={log.path}
        >
          {log.path}
        </td>
        <td className="whitespace-nowrap px-2.5 py-2 text-right font-mono text-[11px] tabular-nums text-secondary">
          {formatDurationMs(log.duration_ms)}
        </td>
        <td className="whitespace-nowrap py-2 pl-2.5 pr-4 text-right font-mono text-[11px] tabular-nums text-secondary">
          {formatBytes(totalSize)}
        </td>
      </tr>

      {isExpanded ? (
        <tr className="bg-surface">
          <td
            colSpan={lockedPrefix ? 8 : 9}
            className="border-t border-border px-5 py-3"
          >
            <div className="flex flex-wrap items-start justify-between gap-4 text-[11px]">
              <dl className="grid flex-1 grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
                <div>
                  <dt className="text-tertiary">Host</dt>
                  <dd className="mt-0.5 font-mono text-foreground">
                    {log.host || "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-tertiary">Client IP</dt>
                  <dd className="mt-0.5 font-mono text-foreground">
                    {log.client_ip || "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-tertiary">流量 (入站 / 出站)</dt>
                  <dd className="mt-0.5 font-mono tabular-nums text-foreground">
                    {formatBytes(log.bytes_in)} / {formatBytes(log.bytes_out)}
                  </dd>
                </div>
                <div className="sm:col-span-2 lg:col-span-3">
                  <dt className="text-tertiary">User-Agent</dt>
                  <dd className="mt-0.5 break-all font-mono text-secondary">
                    {log.user_agent || "—"}
                  </dd>
                </div>
              </dl>

              <div className="flex shrink-0 items-center gap-2">
                {onNavigatePath ? (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onNavigatePath(log.path);
                    }}
                    className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] font-medium text-foreground transition-colors hover:border-border-strong"
                  >
                    在预览中打开
                  </button>
                ) : (
                  <Link
                    href={`/preview/${encodeURIComponent(log.tunnel_prefix)}`}
                    onClick={(e) => e.stopPropagation()}
                    className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] font-medium text-foreground transition-colors hover:border-border-strong"
                  >
                    内嵌预览
                  </Link>
                )}
                <a
                  href={directPath}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="inline-flex h-7 items-center gap-1 rounded-md border border-border bg-background px-2.5 text-[11px] font-medium text-secondary transition-colors hover:border-border-strong hover:text-foreground"
                >
                  <span>新窗口</span>
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
});

export function TrafficInspector({
  logs,
  tunnels = [],
  sseState = "connected",
  compact = false,
  lockedPrefix,
  onNavigatePath,
  canClear = false,
  onClearLogs,
}: TrafficInspectorProps) {
  const [selectedPrefix, setSelectedPrefix] = useState("");
  const [methodFilter, setMethodFilter] = useState<string>("ALL");
  const [viaFilter, setViaFilter] = useState<"all" | "subdomain" | "path">(
    "all",
  );
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [paused, setPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState<RequestLog[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const activePrefix = lockedPrefix !== undefined ? lockedPrefix : selectedPrefix;
  const sourceLogs = paused ? frozenLogs : logs;

  const prefixOptions = useMemo(() => {
    const set = new Set<string>();
    for (const t of tunnels) set.add(t.prefix);
    for (const l of sourceLogs) if (l.tunnel_prefix) set.add(l.tunnel_prefix);
    return Array.from(set).sort();
  }, [tunnels, sourceLogs]);

  const filteredLogs = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    return sourceLogs.filter((log) => {
      if (activePrefix && log.tunnel_prefix !== activePrefix) return false;
      if (viaFilter !== "all" && log.via !== viaFilter) return false;
      if (methodFilter !== "ALL") {
        const m = log.method.toUpperCase();
        if (methodFilter === "WS") {
          if (m !== "WS" && m !== "WEBSOCKET") return false;
        } else if (m !== methodFilter) {
          return false;
        }
      }
      if (q) {
        const hay =
          `${log.method} ${log.status} ${log.tunnel_prefix} ${log.path} ${log.host} ${log.client_ip}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [sourceLogs, activePrefix, viaFilter, methodFilter, deferredQuery]);

  const handleTogglePause = () => {
    setPaused((prev) => {
      if (!prev) {
        setFrozenLogs(logs);
      }
      return !prev;
    });
  };

  const handleToggleRow = (rowKey: string) => {
    setExpandedId((prev) => (prev === rowKey ? null : rowKey));
  };

  const handleClear = async () => {
    if (!onClearLogs) return;
    setClearing(true);
    try {
      await onClearLogs();
      setFrozenLogs([]);
      setConfirmClear(false);
    } finally {
      setClearing(false);
    }
  };

  return (
    <div
      className={
        compact
          ? "flex h-full flex-col bg-background"
          : "overflow-hidden rounded-lg border border-border bg-background"
      }
    >
      {/* Toolbar */}
      <div
        className={`flex flex-wrap items-center justify-between gap-2.5 border-b border-border ${
          compact ? "px-3 py-2" : "px-4 py-3"
        }`}
      >
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-tertiary" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索路径、Host 或 IP"
              aria-label="搜索日志"
              className="h-8 w-44 rounded-md border border-border bg-background pl-8 pr-7 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none sm:w-56"
            />
            {query ? (
              <button
                type="button"
                onClick={() => setQuery("")}
                aria-label="清除搜索"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-tertiary hover:text-foreground"
              >
                <X className="h-3 w-3" />
              </button>
            ) : null}
          </div>

          {/* Prefix select */}
          {!lockedPrefix ? (
            <select
              value={activePrefix}
              onChange={(e) => setSelectedPrefix(e.target.value)}
              aria-label="按隧道筛选"
              className="h-8 rounded-md border border-border bg-background px-2.5 font-mono text-xs text-foreground focus:border-foreground focus:outline-none"
            >
              <option value="">全部隧道 ({prefixOptions.length})</option>
              {prefixOptions.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          ) : null}

          {/* Method select */}
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            aria-label="按请求方法筛选"
            className="h-8 rounded-md border border-border bg-background px-2.5 font-mono text-xs text-foreground focus:border-foreground focus:outline-none"
          >
            {HTTP_METHODS.map((m) => (
              <option key={m} value={m}>
                {m === "ALL" ? "全部方法" : m}
              </option>
            ))}
          </select>

          {/* Via segmented filter */}
          <div className="inline-flex h-8 items-center rounded-md border border-border bg-surface p-0.5 text-xs">
            {(
              [
                { id: "all", label: "全部" },
                { id: "subdomain", label: "泛域名" },
                { id: "path", label: "路径代理" },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setViaFilter(opt.id)}
                className={`h-full rounded px-2 text-[11px] transition-colors ${
                  viaFilter === opt.id
                    ? "bg-background font-medium text-foreground"
                    : "text-secondary hover:text-foreground"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Right actions */}
        <div className="flex items-center gap-2">
          <div className="hidden items-center gap-1.5 text-[11px] text-secondary sm:inline-flex">
            <StatusDot
              tone={
                paused
                  ? "warn"
                  : sseState === "connected"
                    ? "online"
                    : "muted"
              }
            />
            <span className="tabular-nums">
              {paused
                ? "已暂停"
                : sseState === "connected"
                  ? "实时"
                  : "轮询"}
              {" · "}
              {filteredLogs.length} 条
            </span>
          </div>

          <button
            type="button"
            onClick={handleTogglePause}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors ${
              paused
                ? "border-foreground bg-foreground text-background"
                : "border-border bg-background text-foreground hover:border-border-strong"
            }`}
          >
            {paused ? (
              <>
                <Play className="h-3.5 w-3.5" />
                <span>恢复</span>
              </>
            ) : (
              <>
                <Pause className="h-3.5 w-3.5" />
                <span>暂停</span>
              </>
            )}
          </button>

          {canClear && onClearLogs ? (
            confirmClear ? (
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  disabled={clearing}
                  onClick={() => void handleClear()}
                  className="inline-flex h-8 items-center rounded-md border border-red-500/40 bg-red-600 px-2.5 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
                >
                  {clearing ? "清空中..." : "确认清空"}
                </button>
                <button
                  type="button"
                  disabled={clearing}
                  onClick={() => setConfirmClear(false)}
                  className="inline-flex h-8 items-center rounded-md border border-border bg-background px-2 text-xs text-secondary hover:text-foreground"
                >
                  取消
                </button>
              </div>
            ) : (
              <button
                type="button"
                disabled={logs.length === 0}
                onClick={() => setConfirmClear(true)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-background px-2.5 text-xs text-secondary transition-colors hover:border-red-500/40 hover:text-red-600 disabled:opacity-40 dark:hover:text-red-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>清空日志</span>
              </button>
            )
          ) : null}
        </div>
      </div>

      {/* Table */}
      <div
        className={`overflow-auto ${compact ? "flex-1" : "max-h-[calc(100vh-260px)] min-h-[320px]"}`}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <p className="text-xs font-medium text-foreground">
              {sourceLogs.length === 0 ? "暂无流量记录" : "无匹配筛选条件的请求"}
            </p>
            <p className="mt-1 text-xs text-secondary">
              通过泛域名或路径代理访问活跃隧道时，请求将在此实时显示。
            </p>
          </div>
        ) : (
          <table className="w-full min-w-[740px] border-collapse text-left">
            <thead className="sticky top-0 z-10 border-b border-border bg-surface text-[11px] font-medium text-secondary">
              <tr>
                <th className="w-7 py-2 pl-3 pr-1" />
                <th className="whitespace-nowrap px-2.5 py-2">时间</th>
                <th className="whitespace-nowrap px-2.5 py-2">方法</th>
                <th className="whitespace-nowrap px-2.5 py-2">状态</th>
                {!lockedPrefix ? (
                  <th className="whitespace-nowrap px-2.5 py-2">隧道前缀</th>
                ) : null}
                <th className="whitespace-nowrap px-2.5 py-2">入口</th>
                <th className="px-2.5 py-2">路径</th>
                <th className="whitespace-nowrap px-2.5 py-2 text-right">耗时</th>
                <th className="whitespace-nowrap py-2 pl-2.5 pr-4 text-right">
                  流量
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredLogs.map((log, idx) => {
                const rowKey = log.id || `${log.timestamp}-${idx}`;
                return (
                  <LogRow
                    key={rowKey}
                    rowKey={rowKey}
                    log={log}
                    isExpanded={expandedId === rowKey}
                    lockedPrefix={lockedPrefix}
                    onToggle={handleToggleRow}
                    onNavigatePath={onNavigatePath}
                  />
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
