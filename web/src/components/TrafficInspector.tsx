"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Monitor,
  Pause,
  Play,
  Search,
  X,
} from "lucide-react";
import {
  formatBytes,
  formatClockTime,
  formatDurationMs,
} from "@/lib/format";
import type { RequestLog, TunnelInfo } from "@/lib/types";

interface TrafficInspectorProps {
  logs: RequestLog[];
  tunnels?: TunnelInfo[];
  /** Controlled selected tunnel filter (optional) */
  selectedPrefix?: string;
  onSelectedPrefixChange?: (prefix: string) => void;
  /** Compact mode used inside /preview/[prefix] drawer */
  compact?: boolean;
  /** Hide tunnel selector when locked to a single tunnel */
  lockedPrefix?: string;
  /** Callback when user clicks "jump to path" inside preview drawer */
  onNavigatePath?: (path: string) => void;
}

function getMethodStyle(method: string): string {
  switch (method.toUpperCase()) {
    case "GET":
      return "bg-cyan-500/12 text-cyan-700 border-cyan-500/25 dark:text-cyan-300";
    case "POST":
      return "bg-emerald-500/12 text-emerald-700 border-emerald-500/25 dark:text-emerald-300";
    case "PUT":
    case "PATCH":
      return "bg-amber-500/12 text-amber-700 border-amber-500/25 dark:text-amber-300";
    case "DELETE":
      return "bg-rose-500/12 text-rose-700 border-rose-500/25 dark:text-rose-300";
    case "WS":
    case "WEBSOCKET":
      return "bg-violet-500/12 text-violet-700 border-violet-500/25 dark:text-violet-300";
    default:
      return "bg-zinc-500/12 text-zinc-700 border-zinc-500/25 dark:text-zinc-300";
  }
}

function getStatusStyle(status: number): string {
  if (status === 101) {
    return "bg-violet-500/15 text-violet-700 dark:text-violet-300";
  }
  if (status >= 200 && status < 300) {
    return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
  }
  if (status >= 300 && status < 400) {
    return "bg-sky-500/15 text-sky-700 dark:text-sky-300";
  }
  if (status >= 400 && status < 500) {
    return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
  }
  if (status >= 500) {
    return "bg-rose-500/15 text-rose-700 dark:text-rose-300";
  }
  return "bg-zinc-500/15 text-zinc-700 dark:text-zinc-300";
}

export function TrafficInspector({
  logs,
  tunnels = [],
  selectedPrefix,
  onSelectedPrefixChange,
  compact = false,
  lockedPrefix,
  onNavigatePath,
}: TrafficInspectorProps) {
  const [internalPrefix, setInternalPrefix] = useState("");
  const [viaFilter, setViaFilter] = useState<"all" | "subdomain" | "path">("all");
  const [query, setQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState<RequestLog[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const activePrefix =
    lockedPrefix !== undefined
      ? lockedPrefix
      : selectedPrefix !== undefined
        ? selectedPrefix
        : internalPrefix;

  const setPrefix = (val: string) => {
    if (onSelectedPrefixChange) {
      onSelectedPrefixChange(val);
    } else {
      setInternalPrefix(val);
    }
  };

  const sourceLogs = paused ? frozenLogs : logs;

  const prefixOptions = useMemo(() => {
    const set = new Set<string>();
    for (const t of tunnels) set.add(t.prefix);
    for (const l of sourceLogs) if (l.tunnel_prefix) set.add(l.tunnel_prefix);
    return Array.from(set).sort();
  }, [tunnels, sourceLogs]);

  const filteredLogs = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sourceLogs.filter((log) => {
      if (activePrefix && log.tunnel_prefix !== activePrefix) return false;
      if (viaFilter !== "all" && log.via !== viaFilter) return false;
      if (q) {
        const hay =
          `${log.method} ${log.status} ${log.tunnel_prefix} ${log.path} ${log.host} ${log.client_ip}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [sourceLogs, activePrefix, viaFilter, query]);

  const togglePause = () => {
    if (!paused) {
      setFrozenLogs(logs);
      setPaused(true);
    } else {
      setPaused(false);
    }
  };

  return (
    <section
      aria-label="实时流量监控"
      className={
        compact
          ? "flex h-full flex-col bg-white dark:bg-zinc-950"
          : "overflow-hidden rounded-2xl border border-zinc-200/90 bg-white/90 shadow-xs backdrop-blur-md dark:border-zinc-800/80 dark:bg-zinc-900/65"
      }
    >
      {/* Toolbar */}
      <div
        className={`flex flex-wrap items-center justify-between gap-2.5 border-b border-zinc-200/80 dark:border-zinc-800/80 ${
          compact ? "px-3.5 py-2" : "px-5 py-3.5"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/12 text-cyan-600 dark:text-cyan-400">
            <Activity className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                实时流量监控 Live Traffic Inspector
              </h2>
              <span className="rounded-full bg-zinc-100 px-2 py-0.5 font-mono text-[11px] font-medium text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
                {filteredLogs.length}
              </span>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索路径 / 方法 / 状态码..."
              className="w-44 rounded-lg border border-zinc-200 bg-zinc-50 py-1.5 pl-8 pr-7 text-xs text-zinc-800 placeholder:text-zinc-400 focus:border-cyan-500 focus:bg-white focus:outline-none sm:w-52 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-100 dark:placeholder:text-zinc-500"
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                aria-label="清除搜索"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          {/* Tunnel Selector */}
          {!lockedPrefix && (
            <select
              value={activePrefix}
              onChange={(e) => setPrefix(e.target.value)}
              aria-label="按隧道前缀筛选"
              className="rounded-lg border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 font-mono text-xs text-zinc-700 focus:border-cyan-500 focus:outline-none dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-200"
            >
              <option value="">全部隧道 ({prefixOptions.length})</option>
              {prefixOptions.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          )}

          {/* Via filter */}
          <div className="inline-flex rounded-lg border border-zinc-200 bg-zinc-100/80 p-0.5 text-[11px] dark:border-zinc-800 dark:bg-zinc-950">
            {(
              [
                { id: "all", label: "全部" },
                { id: "subdomain", label: "泛域名" },
                { id: "path", label: "Web代理" },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setViaFilter(opt.id)}
                className={`rounded-md px-2 py-1 font-medium transition ${
                  viaFilter === opt.id
                    ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-800 dark:text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Pause / Resume */}
          <button
            type="button"
            onClick={togglePause}
            className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
              paused
                ? "border-amber-500/40 bg-amber-500/12 text-amber-700 dark:text-amber-300"
                : "border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
            }`}
            title={paused ? "恢复实时日志流" : "暂停滚动以检查请求详情"}
          >
            {paused ? (
              <>
                <Play className="h-3 w-3" />
                恢复
              </>
            ) : (
              <>
                <Pause className="h-3 w-3" />
                暂停
              </>
            )}
          </button>
        </div>
      </div>

      {/* Table */}
      <div
        className={`overflow-auto ${compact ? "flex-1" : "max-h-[460px]"}`}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
            <Activity className="h-8 w-8 text-zinc-300 dark:text-zinc-700" />
            <p className="mt-2.5 text-xs font-medium text-zinc-600 dark:text-zinc-400">
              {sourceLogs.length === 0
                ? "暂无实时流量记录"
                : "没有匹配当前筛选条件的请求"}
            </p>
            <p className="mt-1 text-[11px] text-zinc-400 dark:text-zinc-500">
              通过泛域名或 /t/&lt;prefix&gt;/ 访问隧道服务时，请求会在此实时呈现。
            </p>
          </div>
        ) : (
          <table className="w-full min-w-[740px] border-collapse text-left text-xs">
            <thead className="sticky top-0 z-10 border-b border-zinc-200/80 bg-zinc-50/95 text-[11px] font-medium text-zinc-500 backdrop-blur-sm dark:border-zinc-800/80 dark:bg-zinc-950/95 dark:text-zinc-400">
              <tr>
                <th className="w-7 py-2 pl-3 pr-1" />
                <th className="whitespace-nowrap px-2.5 py-2">时间</th>
                <th className="whitespace-nowrap px-2.5 py-2">方法</th>
                <th className="whitespace-nowrap px-2.5 py-2">状态</th>
                {!lockedPrefix && (
                  <th className="whitespace-nowrap px-2.5 py-2">隧道前缀</th>
                )}
                <th className="whitespace-nowrap px-2.5 py-2">入口</th>
                <th className="px-2.5 py-2">请求路径 Path</th>
                <th className="whitespace-nowrap px-2.5 py-2 text-right">耗时</th>
                <th className="whitespace-nowrap py-2 pl-2.5 pr-4 text-right">
                  大小
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/70">
              {filteredLogs.map((log, idx) => {
                const rowKey = log.id || `${log.timestamp}-${idx}`;
                const isExpanded = expandedId === rowKey;
                const totalSize = (log.bytes_in || 0) + (log.bytes_out || 0);
                return (
                  <React.Fragment key={rowKey}>
                    <tr
                      onClick={() =>
                        setExpandedId(isExpanded ? null : rowKey)
                      }
                      className={`cursor-pointer transition hover:bg-zinc-50/90 dark:hover:bg-zinc-800/40 ${
                        isExpanded ? "bg-cyan-500/[0.04]" : ""
                      }`}
                    >
                      <td className="py-2 pl-3 pr-1 text-zinc-400">
                        {isExpanded ? (
                          <ChevronDown className="h-3.5 w-3.5" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5" />
                        )}
                      </td>
                      <td className="whitespace-nowrap px-2.5 py-2 font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                        {formatClockTime(log.timestamp)}
                      </td>
                      <td className="whitespace-nowrap px-2.5 py-2">
                        <span
                          className={`inline-block rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${getMethodStyle(
                            log.method,
                          )}`}
                        >
                          {log.method}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-2.5 py-2">
                        <span
                          className={`inline-block rounded-md px-1.5 py-0.5 font-mono text-[11px] font-semibold ${getStatusStyle(
                            log.status,
                          )}`}
                        >
                          {log.status}
                        </span>
                      </td>
                      {!lockedPrefix && (
                        <td className="whitespace-nowrap px-2.5 py-2">
                          <Link
                            href={`/preview/${encodeURIComponent(log.tunnel_prefix)}`}
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex max-w-[140px] items-center gap-1 truncate rounded-md bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] text-zinc-700 hover:bg-cyan-500/15 hover:text-cyan-700 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:text-cyan-300"
                            title={`在 Web 内嵌预览中打开 ${log.tunnel_prefix}`}
                          >
                            <span className="truncate">{log.tunnel_prefix}</span>
                          </Link>
                        </td>
                      )}
                      <td className="whitespace-nowrap px-2.5 py-2">
                        <span
                          className={`inline-block rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                            log.via === "path"
                              ? "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300"
                              : "bg-cyan-500/12 text-cyan-700 dark:text-cyan-300"
                          }`}
                        >
                          {log.via === "path" ? "Web代理" : "泛域名"}
                        </span>
                      </td>
                      <td className="max-w-[320px] truncate px-2.5 py-2 font-mono text-[11px] text-zinc-800 dark:text-zinc-200" title={log.path}>
                        {log.path}
                      </td>
                      <td className="whitespace-nowrap px-2.5 py-2 text-right font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
                        {formatDurationMs(log.duration_ms)}
                      </td>
                      <td className="whitespace-nowrap py-2 pl-2.5 pr-4 text-right font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                        {formatBytes(totalSize)}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-zinc-50/80 dark:bg-zinc-950/75">
                        <td colSpan={lockedPrefix ? 8 : 9} className="px-5 py-3">
                          <div className="flex flex-wrap items-start justify-between gap-4 text-[11px]">
                            <dl className="grid flex-1 grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">
                              <div>
                                <dt className="text-zinc-400 dark:text-zinc-500">
                                  Host
                                </dt>
                                <dd className="font-mono text-zinc-700 dark:text-zinc-200">
                                  {log.host || "—"}
                                </dd>
                              </div>
                              <div>
                                <dt className="text-zinc-400 dark:text-zinc-500">
                                  Client IP
                                </dt>
                                <dd className="font-mono text-zinc-700 dark:text-zinc-200">
                                  {log.client_ip || "—"}
                                </dd>
                              </div>
                              <div>
                                <dt className="text-zinc-400 dark:text-zinc-500">
                                  流量明细 (In / Out)
                                </dt>
                                <dd className="font-mono text-zinc-700 dark:text-zinc-200">
                                  ↓ {formatBytes(log.bytes_in)} / ↑{" "}
                                  {formatBytes(log.bytes_out)}
                                </dd>
                              </div>
                              <div className="sm:col-span-2 lg:col-span-3">
                                <dt className="text-zinc-400 dark:text-zinc-500">
                                  User-Agent
                                </dt>
                                <dd className="break-all font-mono text-zinc-600 dark:text-zinc-300">
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
                                  className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-medium text-cyan-700 transition hover:bg-cyan-500/20 dark:text-cyan-300"
                                >
                                  <Monitor className="h-3 w-3" />
                                  在预览中打开此路径
                                </button>
                              ) : (
                                <Link
                                  href={`/preview/${encodeURIComponent(log.tunnel_prefix)}`}
                                  onClick={(e) => e.stopPropagation()}
                                  className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-medium text-cyan-700 transition hover:bg-cyan-500/20 dark:text-cyan-300"
                                >
                                  <Monitor className="h-3 w-3" />
                                  打开预览
                                </Link>
                              )}
                              <a
                                href={`/t/${encodeURIComponent(log.tunnel_prefix)}${log.path.startsWith("/") ? log.path : `/${log.path}`}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="inline-flex items-center gap-1 rounded-lg border border-zinc-200 bg-white px-2.5 py-1 text-[11px] font-medium text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
                              >
                                <ExternalLink className="h-3 w-3" />
                                新窗口
                              </a>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
