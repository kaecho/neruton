"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowDownUp,
  Check,
  Clock,
  Copy,
  Cpu,
  ExternalLink,
  Filter,
  Gauge,
  Globe,
  Layers,
  Monitor,
  Power,
  Route,
  Server,
} from "lucide-react";
import { resolvePathUrl, resolveWildcardUrl } from "@/lib/api";
import {
  copyToClipboard,
  formatBytes,
  formatConnectedDuration,
  formatDurationMs,
  formatNumber,
  isUuidLike,
} from "@/lib/format";
import type { ServerInfo, TunnelInfo } from "@/lib/types";

interface TunnelCardProps {
  tunnel: TunnelInfo;
  info: ServerInfo | null;
  nowMs: number;
  isDisconnecting: boolean;
  onDisconnect: (prefix: string) => void;
  onFilterLogs: (prefix: string) => void;
}

export function TunnelCard({
  tunnel,
  info,
  nowMs,
  isDisconnecting,
  onDisconnect,
  onFilterLogs,
}: TunnelCardProps) {
  const [copiedKey, setCopiedKey] = useState<"wildcard" | "path" | null>(null);
  const [confirming, setConfirming] = useState(false);

  const wildcardUrl = resolveWildcardUrl(tunnel.prefix, info, tunnel);
  const pathUrl = resolvePathUrl(tunnel.prefix, info, tunnel);
  const previewHref = `/preview/${encodeURIComponent(tunnel.prefix)}`;
  const relativePathHref = `/t/${encodeURIComponent(tunnel.prefix)}/`;
  const uuidPrefix = isUuidLike(tunnel.prefix);

  const handleCopy = async (key: "wildcard" | "path", value: string) => {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1600);
    }
  };

  const latencyColor =
    tunnel.latency_ms === null || tunnel.latency_ms === undefined
      ? "text-zinc-400"
      : tunnel.latency_ms < 80
        ? "text-emerald-600 dark:text-emerald-400"
        : tunnel.latency_ms < 220
          ? "text-amber-600 dark:text-amber-400"
          : "text-rose-600 dark:text-rose-400";

  return (
    <article className="group relative flex flex-col justify-between rounded-2xl border border-zinc-200/90 bg-white/90 p-5 shadow-xs backdrop-blur-md transition duration-200 hover:border-cyan-500/40 hover:shadow-md dark:border-zinc-800/80 dark:bg-zinc-900/70 dark:hover:border-cyan-500/40">
      {/* Top Bar: Identity + Status + Disconnect */}
      <div>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="relative flex h-2.5 w-2.5 shrink-0">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
              </span>
              <span
                className="truncate rounded-lg border border-zinc-200 bg-zinc-100/90 px-2 py-0.5 font-mono text-sm font-semibold text-zinc-900 dark:border-zinc-700/80 dark:bg-zinc-800/90 dark:text-zinc-50"
                title={tunnel.prefix}
              >
                {tunnel.prefix}
              </span>
              <span
                className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                  uuidPrefix
                    ? "bg-cyan-500/12 text-cyan-700 dark:text-cyan-300"
                    : "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300"
                }`}
              >
                {uuidPrefix ? "UUID" : "自定义前缀"}
              </span>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500 dark:text-zinc-400">
              <span className="inline-flex items-center gap-1 font-mono" title="本地目标服务">
                <Server className="h-3 w-3 text-zinc-400" />
                {tunnel.target_url}
              </span>
              <span className="inline-flex items-center gap-1" title="客户端环境">
                <Cpu className="h-3 w-3 text-zinc-400" />
                {tunnel.client_os || "unknown"}
                {tunnel.client_version ? ` · v${tunnel.client_version.replace(/^v/, "")}` : ""}
              </span>
              <span className={`inline-flex items-center gap-1 font-mono font-medium ${latencyColor}`}>
                <Gauge className="h-3 w-3" />
                {formatDurationMs(tunnel.latency_ms)}
              </span>
            </div>
          </div>

          {/* Disconnect action with 2-step confirmation */}
          <div className="shrink-0">
            {confirming ? (
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  disabled={isDisconnecting}
                  onClick={() => {
                    setConfirming(false);
                    onDisconnect(tunnel.prefix);
                  }}
                  className="rounded-lg bg-rose-600 px-2.5 py-1 text-[11px] font-medium text-white transition hover:bg-rose-500 disabled:opacity-50"
                >
                  {isDisconnecting ? "断开中..." : "确认断开"}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirming(false)}
                  className="rounded-lg border border-zinc-200 px-2 py-1 text-[11px] text-zinc-500 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-400 dark:hover:bg-zinc-800"
                >
                  取消
                </button>
              </div>
            ) : (
              <button
                type="button"
                disabled={isDisconnecting}
                onClick={() => setConfirming(true)}
                className="inline-flex items-center gap-1 rounded-lg border border-zinc-200/90 px-2.5 py-1.5 text-[11px] font-medium text-zinc-500 transition hover:border-rose-500/40 hover:bg-rose-500/10 hover:text-rose-600 disabled:opacity-50 dark:border-zinc-800 dark:text-zinc-400 dark:hover:border-rose-500/40 dark:hover:text-rose-400"
                title="强制断开此隧道"
              >
                <Power className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">断开</span>
              </button>
            )}
          </div>
        </div>

        {/* Primary Action Buttons: Direct Web Viewer & Path Proxy */}
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Link
            href={previewHref}
            className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-3.5 py-2 text-xs font-semibold text-zinc-950 shadow-xs transition hover:brightness-110"
          >
            <Monitor className="h-3.5 w-3.5" />
            Web 内嵌预览
          </Link>
          <a
            href={relativePathHref}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-medium text-zinc-700 transition hover:border-cyan-500/40 hover:bg-cyan-500/8 hover:text-cyan-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-200 dark:hover:text-cyan-300"
            title="直接在新标签页打开路径代理"
          >
            <Route className="h-3.5 w-3.5" />
            路径直达
            <ExternalLink className="h-3 w-3 opacity-70" />
          </a>
        </div>

        {/* URL Endpoints */}
        <div className="mt-3.5 space-y-2 rounded-xl border border-zinc-200/80 bg-zinc-50/75 p-2.5 dark:border-zinc-800/80 dark:bg-zinc-950/60">
          {/* Wildcard Subdomain URL */}
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <Globe className="h-3 w-3 text-cyan-500" />
                泛域名访问 Wildcard URL
              </div>
              <a
                href={wildcardUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-0.5 block truncate font-mono text-xs font-medium text-cyan-700 hover:underline dark:text-cyan-300"
                title={wildcardUrl}
              >
                {wildcardUrl}
              </a>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <button
                type="button"
                onClick={() => handleCopy("wildcard", wildcardUrl)}
                className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-zinc-200 bg-white text-zinc-500 transition hover:border-cyan-500/40 hover:text-cyan-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:text-cyan-300"
                title="复制泛域名链接"
              >
                {copiedKey === "wildcard" ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
              </button>
              <a
                href={wildcardUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-zinc-200 bg-white text-zinc-500 transition hover:border-cyan-500/40 hover:text-cyan-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:text-cyan-300"
                title="新窗口打开泛域名"
              >
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>

          <div className="border-t border-zinc-200/70 dark:border-zinc-800/70" />

          {/* Path Proxy URL */}
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <Route className="h-3 w-3 text-emerald-500" />
                路径代理 Path URL
              </div>
              <a
                href={relativePathHref}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-0.5 block truncate font-mono text-[11px] text-zinc-600 hover:text-zinc-900 hover:underline dark:text-zinc-300 dark:hover:text-zinc-100"
                title={pathUrl}
              >
                {pathUrl}
              </a>
            </div>
            <button
              type="button"
              onClick={() => handleCopy("path", pathUrl)}
              className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-zinc-200 bg-white text-zinc-500 transition hover:border-emerald-500/40 hover:text-emerald-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:text-emerald-300"
              title="复制路径代理链接"
            >
              {copiedKey === "path" ? (
                <Check className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Telemetry Strip */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200/75 pt-3 text-[11px] text-zinc-500 dark:border-zinc-800/75 dark:text-zinc-400">
        <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1">
          <span className="inline-flex items-center gap-1" title="请求总数">
            <Activity className="h-3 w-3 text-cyan-500" />
            <span className="font-mono font-medium text-zinc-700 dark:text-zinc-200">
              {formatNumber(tunnel.requests_total)}
            </span>{" "}
            req
          </span>
          <span className="inline-flex items-center gap-1" title={`入站 ${formatBytes(tunnel.bytes_in)} / 出站 ${formatBytes(tunnel.bytes_out)}`}>
            <ArrowDownUp className="h-3 w-3 text-sky-500" />
            <span className="font-mono text-zinc-700 dark:text-zinc-300">
              ↓{formatBytes(tunnel.bytes_in)}
            </span>
            <span className="text-zinc-300 dark:text-zinc-700">/</span>
            <span className="font-mono text-zinc-700 dark:text-zinc-300">
              ↑{formatBytes(tunnel.bytes_out)}
            </span>
          </span>
          <span className="inline-flex items-center gap-1" title="当前并发流">
            <Layers className="h-3 w-3 text-violet-500" />
            <span className="font-mono">{tunnel.active_streams}</span>
          </span>
          <span className="inline-flex items-center gap-1" title={`客户端 IP: ${tunnel.remote_addr}`}>
            <Clock className="h-3 w-3 text-zinc-400" />
            <span className="font-mono">
              {formatConnectedDuration(tunnel.connected_at, nowMs)}
            </span>
          </span>
        </div>

        <button
          type="button"
          onClick={() => onFilterLogs(tunnel.prefix)}
          className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium text-cyan-600 transition hover:bg-cyan-500/10 dark:text-cyan-400"
        >
          <Filter className="h-3 w-3" />
          筛选日志
        </button>
      </div>
    </article>
  );
}
