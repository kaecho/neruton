"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownUp,
  Clock,
  Lock,
  Radio,
  Unlock,
} from "lucide-react";
import { formatBytes, formatNumber, formatUptime } from "@/lib/format";
import type { ServerInfo, TunnelInfo } from "@/lib/types";

interface KpiStatsRowProps {
  info: ServerInfo | null;
  tunnels: TunnelInfo[];
  isLoading: boolean;
}

export function KpiStatsRow({ info, tunnels, isLoading }: KpiStatsRowProps) {
  const [tickDelta, setTickDelta] = useState(0);

  useEffect(() => {
    setTickDelta(0);
    if (!info) return;
    const timer = setInterval(() => {
      setTickDelta((d) => d + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [info]);

  const { totalBytesIn, totalBytesOut, activeStreams } = useMemo(() => {
    return tunnels.reduce(
      (acc, t) => ({
        totalBytesIn: acc.totalBytesIn + (t.bytes_in || 0),
        totalBytesOut: acc.totalBytesOut + (t.bytes_out || 0),
        activeStreams: acc.activeStreams + (t.active_streams || 0),
      }),
      { totalBytesIn: 0, totalBytesOut: 0, activeStreams: 0 },
    );
  }, [tunnels]);

  const activeCount = info ? Math.max(tunnels.length, info.active_tunnels) : tunnels.length;
  const totalRequests = info?.total_requests ?? tunnels.reduce((s, t) => s + (t.requests_total || 0), 0);
  const liveUptime = info ? info.uptime_secs + tickDelta : 0;

  return (
    <section
      aria-label="网关核心指标"
      className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4"
    >
      {/* Active Tunnels */}
      <div className="group relative overflow-hidden rounded-2xl border border-zinc-200/90 bg-white/85 p-4 shadow-xs backdrop-blur-md transition hover:border-emerald-500/40 dark:border-zinc-800/80 dark:bg-zinc-900/65">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
            活跃隧道 Active Tunnels
          </span>
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <Radio className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-3 flex items-baseline gap-2.5">
          <span className="font-mono text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            {isLoading && !info ? "—" : formatNumber(activeCount)}
          </span>
          {activeCount > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/12 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              在线
            </span>
          )}
        </div>
        <p className="mt-1.5 text-[11px] text-zinc-500 dark:text-zinc-400">
          当前复用并发流:{" "}
          <span className="font-mono font-medium text-zinc-700 dark:text-zinc-300">
            {formatNumber(activeStreams)}
          </span>
        </p>
      </div>

      {/* Total Requests */}
      <div className="group relative overflow-hidden rounded-2xl border border-zinc-200/90 bg-white/85 p-4 shadow-xs backdrop-blur-md transition hover:border-cyan-500/40 dark:border-zinc-800/80 dark:bg-zinc-900/65">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
            累计请求 Total Requests
          </span>
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
            <Activity className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            {isLoading && !info ? "—" : formatNumber(totalRequests)}
          </span>
          <span className="text-xs text-zinc-400 dark:text-zinc-500">req</span>
        </div>
        <p className="mt-1.5 text-[11px] text-zinc-500 dark:text-zinc-400">
          泛域名 + 路径代理 HTTP / WebSocket 总转发
        </p>
      </div>

      {/* Total Bandwidth */}
      <div className="group relative overflow-hidden rounded-2xl border border-zinc-200/90 bg-white/85 p-4 shadow-xs backdrop-blur-md transition hover:border-sky-500/40 dark:border-zinc-800/80 dark:bg-zinc-900/65">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
            活跃流量 Active Bandwidth
          </span>
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400">
            <ArrowDownUp className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            {isLoading && !info ? "—" : formatBytes(totalBytesIn + totalBytesOut)}
          </span>
        </div>
        <div className="mt-1.5 flex items-center gap-3 text-[11px] text-zinc-500 dark:text-zinc-400">
          <span>
            ↓ 入站{" "}
            <span className="font-mono font-medium text-zinc-700 dark:text-zinc-300">
              {formatBytes(totalBytesIn)}
            </span>
          </span>
          <span>
            ↑ 出站{" "}
            <span className="font-mono font-medium text-zinc-700 dark:text-zinc-300">
              {formatBytes(totalBytesOut)}
            </span>
          </span>
        </div>
      </div>

      {/* Server Uptime & Version */}
      <div className="group relative overflow-hidden rounded-2xl border border-zinc-200/90 bg-white/85 p-4 shadow-xs backdrop-blur-md transition hover:border-violet-500/40 dark:border-zinc-800/80 dark:bg-zinc-900/65">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
            网关运行时间 Uptime
          </span>
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-violet-500/10 text-violet-600 dark:text-violet-400">
            <Clock className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            {info ? formatUptime(liveUptime) : "—"}
          </span>
        </div>
        <div className="mt-1.5 flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400">
          <span className="font-mono">
            neruton-server {info?.version ? `v${info.version.replace(/^v/, "")}` : "—"}
          </span>
          {info && (
            <span
              className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                info.auth_required
                  ? "bg-amber-500/12 text-amber-700 dark:text-amber-300"
                  : "bg-zinc-200/80 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
              }`}
            >
              {info.auth_required ? (
                <>
                  <Lock className="h-2.5 w-2.5" /> 令牌保护
                </>
              ) : (
                <>
                  <Unlock className="h-2.5 w-2.5" /> 开放接入
                </>
              )}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
