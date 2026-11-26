"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowRight,
  ExternalLink,
  Globe,
  Home,
  Laptop,
  Maximize2,
  Minimize2,
  PanelBottom,
  PanelBottomClose,
  RefreshCw,
  RotateCw,
  Route,
  Smartphone,
  Tablet,
  WifiOff,
} from "lucide-react";
import { Logo } from "@/components/Logo";
import { QuickStartCli } from "@/components/QuickStartCli";
import { TrafficInspector } from "@/components/TrafficInspector";
import { useNerutonStream } from "@/hooks/useNerutonStream";
import {
  fetchTunnel,
  getStoredAdminToken,
  resolveWildcardUrl,
} from "@/lib/api";
import { formatDurationMs } from "@/lib/format";
import type { TunnelInfo, ViewportMode } from "@/lib/types";

interface PreviewViewerClientProps {
  prefix: string;
}

function normalizeSubPath(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

export function PreviewViewerClient({ prefix }: PreviewViewerClientProps) {
  const { info, tunnels, logs, sseState, isLoading, refresh } =
    useNerutonStream({ prefixFilter: prefix });

  const [directTunnel, setDirectTunnel] = useState<TunnelInfo | null>(null);
  const [tunnelChecked, setTunnelChecked] = useState(false);
  const [subPath, setSubPath] = useState("/");
  const [addressInput, setAddressInput] = useState("/");
  const [reloadNonce, setReloadNonce] = useState(0);
  const [iframeLoading, setIframeLoading] = useState(true);
  const [viewport, setViewport] = useState<ViewportMode>("desktop");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerExpanded, setDrawerExpanded] = useState(false);
  const [isChecking, setIsChecking] = useState(false);
  const [adminToken, setAdminToken] = useState("");

  useEffect(() => {
    setAdminToken(getStoredAdminToken());
  }, []);

  const checkDirectTunnel = useCallback(async () => {
    setIsChecking(true);
    try {
      const found = await fetchTunnel(prefix);
      setDirectTunnel(found);
    } catch {
      // keep existing state on transient error
    } finally {
      setTunnelChecked(true);
      setTimeout(() => setIsChecking(false), 300);
    }
  }, [prefix]);

  useEffect(() => {
    void checkDirectTunnel();
  }, [checkDirectTunnel]);

  const activeTunnel = useMemo(() => {
    const fromStream = tunnels.find((t) => t.prefix === prefix);
    if (fromStream) return fromStream;
    if (!isLoading && tunnelChecked) return directTunnel;
    return directTunnel;
  }, [tunnels, prefix, isLoading, tunnelChecked, directTunnel]);

  // If the stream indicates the tunnel disconnected, clear stale directTunnel
  useEffect(() => {
    if (!isLoading) {
      const inStream = tunnels.find((t) => t.prefix === prefix) ?? null;
      setDirectTunnel(inStream);
      setTunnelChecked(true);
    }
  }, [tunnels, prefix, isLoading]);

  const isOnline = Boolean(activeTunnel);
  const isInitialChecking = !tunnelChecked && isLoading;

  const encodedPrefix = encodeURIComponent(prefix);
  const normalizedPath = normalizeSubPath(subPath);
  const baseIframePath = `/t/${encodedPrefix}${normalizedPath}`;
  const iframeSrc =
    reloadNonce > 0
      ? `${baseIframePath}${baseIframePath.includes("?") ? "&" : "?"}_neruton_reload=${reloadNonce}`
      : baseIframePath;

  const wildcardUrl = resolveWildcardUrl(prefix, info, activeTunnel);

  const navigateToSubPath = useCallback((nextRaw: string) => {
    const normalized = normalizeSubPath(nextRaw);
    setSubPath(normalized);
    setAddressInput(normalized);
    setIframeLoading(true);
  }, []);

  const handleAddressSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    navigateToSubPath(addressInput);
  };

  const handleReload = () => {
    setIframeLoading(true);
    setReloadNonce((n) => n + 1);
  };

  const handleRetryOnline = async () => {
    await Promise.all([refresh(), checkDirectTunnel()]);
    setIframeLoading(true);
    setReloadNonce((n) => n + 1);
  };

  const viewportFrameClass =
    viewport === "desktop"
      ? "h-full w-full"
      : viewport === "tablet"
        ? "h-full w-full max-w-[768px] rounded-t-2xl border-x border-t border-zinc-300 shadow-2xl dark:border-zinc-700"
        : "h-full w-full max-w-[390px] rounded-t-[2rem] border-x-[6px] border-t-[6px] border-zinc-800 shadow-2xl dark:border-zinc-700";

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-zinc-100 text-zinc-900 dark:bg-[#09090b] dark:text-zinc-100">
      {/* Browser-like Top Toolbar */}
      <header className="z-20 shrink-0 border-b border-zinc-200/90 bg-white/95 px-3 py-2 backdrop-blur-md dark:border-zinc-800/90 dark:bg-zinc-950/95">
        <div className="flex flex-wrap items-center gap-2">
          {/* Left: Back + Brand + Tunnel Status */}
          <div className="flex items-center gap-2">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800"
              title="返回 Neruton 控制台"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">控制台</span>
            </Link>

            <div className="hidden items-center gap-2 sm:flex">
              <Logo className="h-6 w-6" />
              <div className="flex items-center gap-1.5 rounded-xl border border-zinc-200/90 bg-zinc-100/80 px-2.5 py-1 dark:border-zinc-800 dark:bg-zinc-900">
                <span
                  className={`h-2 w-2 rounded-full ${
                    isOnline
                      ? "bg-emerald-500 animate-pulse"
                      : isInitialChecking
                        ? "bg-cyan-500 animate-pulse"
                        : "bg-rose-500"
                  }`}
                />
                <span
                  className="max-w-[140px] truncate font-mono text-xs font-semibold text-zinc-800 dark:text-zinc-100"
                  title={prefix}
                >
                  {prefix}
                </span>
                {activeTunnel && (
                  <span className="hidden text-[10px] font-mono text-zinc-400 xl:inline">
                    · {formatDurationMs(activeTunnel.latency_ms)}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Center: Interactive Sub-Path Address Bar */}
          <form
            onSubmit={handleAddressSubmit}
            className="order-last flex min-w-0 flex-1 basis-full items-center gap-1.5 md:order-none md:basis-auto"
          >
            <button
              type="button"
              onClick={handleReload}
              disabled={!isOnline}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-zinc-200 bg-zinc-50 text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 disabled:opacity-40 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
              title="刷新内嵌页面"
              aria-label="刷新内嵌页面"
            >
              <RotateCw
                className={`h-3.5 w-3.5 ${iframeLoading && isOnline ? "animate-spin" : ""}`}
              />
            </button>

            <button
              type="button"
              onClick={() => navigateToSubPath("/")}
              disabled={!isOnline}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-zinc-200 bg-zinc-50 text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 disabled:opacity-40 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
              title="回到根路径 (/)"
              aria-label="回到根路径"
            >
              <Home className="h-3.5 w-3.5" />
            </button>

            <div className="flex min-w-0 flex-1 items-center overflow-hidden rounded-xl border border-zinc-300 bg-zinc-50 focus-within:border-cyan-500 focus-within:bg-white focus-within:ring-2 focus-within:ring-cyan-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:focus-within:bg-zinc-950">
              <span
                className="shrink-0 select-none border-r border-zinc-200 bg-zinc-100 px-2.5 py-1.5 font-mono text-[11px] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400"
                title={
                  activeTunnel
                    ? `目标服务: ${activeTunnel.target_url}`
                    : `/t/${prefix}`
                }
              >
                /t/{prefix.length > 16 ? `${prefix.slice(0, 12)}…` : prefix}
              </span>
              <input
                type="text"
                value={addressInput}
                onChange={(e) => setAddressInput(e.target.value)}
                placeholder="/api/health"
                aria-label="隧道子路径地址栏"
                className="min-w-0 flex-1 bg-transparent px-2.5 py-1.5 font-mono text-xs text-zinc-900 placeholder:text-zinc-400 focus:outline-none dark:text-zinc-100"
              />
              <button
                type="submit"
                disabled={!isOnline}
                className="inline-flex h-7 items-center gap-1 rounded-lg bg-cyan-500/15 px-2 mr-1 text-[11px] font-medium text-cyan-700 transition hover:bg-cyan-500/25 disabled:opacity-40 dark:text-cyan-300"
                title="跳转到此子路径"
              >
                <span className="hidden sm:inline">前往</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          </form>

          {/* Right: Viewport Switcher + External Links + Log Drawer Toggle */}
          <div className="ml-auto flex items-center gap-1.5">
            {/* Viewport Switcher */}
            <div
              className="hidden items-center rounded-xl border border-zinc-200 bg-zinc-100/80 p-0.5 sm:inline-flex dark:border-zinc-800 dark:bg-zinc-900"
              role="group"
              aria-label="切换预览视口宽度"
            >
              {(
                [
                  { id: "desktop", icon: Laptop, label: "桌面端 (100%)" },
                  { id: "tablet", icon: Tablet, label: "平板 (768px)" },
                  { id: "mobile", icon: Smartphone, label: "手机 (390px)" },
                ] as const
              ).map((item) => {
                const Icon = item.icon;
                const active = viewport === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setViewport(item.id)}
                    title={item.label}
                    aria-label={item.label}
                    className={`rounded-lg p-1.5 transition ${
                      active
                        ? "bg-white text-cyan-600 shadow-xs dark:bg-zinc-800 dark:text-cyan-300"
                        : "text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                  </button>
                );
              })}
            </div>

            {/* Open Wildcard Domain */}
            <a
              href={wildcardUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-xl border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 text-xs font-medium text-zinc-700 transition hover:border-cyan-500/40 hover:text-cyan-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:text-cyan-300"
              title={`新窗口打开泛域名: ${wildcardUrl}`}
            >
              <Globe className="h-3.5 w-3.5 text-cyan-500" />
              <span className="hidden xl:inline">泛域名</span>
              <ExternalLink className="h-3 w-3 opacity-65" />
            </a>

            {/* Open Direct Path */}
            <a
              href={baseIframePath}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-xl border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 text-xs font-medium text-zinc-700 transition hover:border-emerald-500/40 hover:text-emerald-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:text-emerald-300"
              title={`新窗口直接打开路径代理: ${baseIframePath}`}
            >
              <Route className="h-3.5 w-3.5 text-emerald-500" />
              <span className="hidden xl:inline">路径直达</span>
              <ExternalLink className="h-3 w-3 opacity-65" />
            </a>

            {/* Toggle Live Request Log Drawer */}
            <button
              type="button"
              onClick={() => setDrawerOpen((o) => !o)}
              className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition ${
                drawerOpen
                  ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-700 dark:text-cyan-300"
                  : "border-zinc-200 bg-zinc-50 text-zinc-700 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800"
              }`}
              title="展开/收起实时请求日志抽屉"
            >
              {drawerOpen ? (
                <PanelBottomClose className="h-3.5 w-3.5" />
              ) : (
                <PanelBottom className="h-3.5 w-3.5" />
              )}
              <span className="hidden lg:inline">请求日志</span>
              <span className="rounded-md bg-zinc-200/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                {logs.length}
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Preview Stage */}
      <main className="relative flex min-h-0 flex-1 flex-col overflow-hidden bg-zinc-200/70 dark:bg-zinc-950">
        {isInitialChecking ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 text-xs text-zinc-500 dark:text-zinc-400">
            <RefreshCw className="h-6 w-6 animate-spin text-cyan-500" />
            <p>正在连接隧道 <span className="font-mono font-semibold">{prefix}</span> ...</p>
          </div>
        ) : isOnline ? (
          <div
            className={`relative flex min-h-0 flex-1 flex-col items-center overflow-hidden ${
              viewport === "desktop" ? "" : "px-4 pt-4"
            }`}
          >
            {/* Device viewport badge when tablet/mobile */}
            {viewport !== "desktop" && (
              <div className="mb-2 flex items-center gap-2 rounded-full border border-zinc-300/80 bg-white/85 px-3 py-1 font-mono text-[11px] text-zinc-600 shadow-xs dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400">
                <span>
                  {viewport === "tablet" ? "Tablet · 768px" : "Mobile · 390px"}
                </span>
                <span className="text-zinc-300 dark:text-zinc-700">|</span>
                <span className="truncate max-w-[220px]">{activeTunnel?.target_url}</span>
              </div>
            )}

            {/* Loading shimmer bar */}
            {iframeLoading && (
              <div className="absolute inset-x-0 top-0 z-10 h-0.5 overflow-hidden bg-cyan-500/20">
                <div className="h-full w-1/3 animate-pulse bg-gradient-to-r from-cyan-400 to-emerald-400" />
              </div>
            )}

            <div className={`relative overflow-hidden bg-white ${viewportFrameClass}`}>
              <iframe
                key={`${prefix}-${normalizedPath}-${reloadNonce}`}
                src={iframeSrc}
                title={`Neruton 预览: ${prefix}`}
                onLoad={() => setIframeLoading(false)}
                className="h-full w-full border-0 bg-white"
                allow="clipboard-read; clipboard-write; fullscreen"
              />
            </div>
          </div>
        ) : (
          /* Graceful Offline / Not Found State */
          <div className="neruton-grid-bg flex-1 overflow-y-auto px-4 py-10">
            <div className="mx-auto max-w-3xl space-y-5">
              <div className="rounded-2xl border border-rose-500/30 bg-white/90 p-6 text-center shadow-sm backdrop-blur-md dark:border-rose-500/25 dark:bg-zinc-900/75">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-rose-500/12 text-rose-600 dark:text-rose-400">
                  <WifiOff className="h-6 w-6" />
                </div>
                <h1 className="mt-3 text-base font-semibold text-zinc-900 dark:text-zinc-100">
                  隧道当前未在线或不存在
                </h1>
                <p className="mt-1.5 text-xs text-zinc-500 dark:text-zinc-400">
                  未找到前缀为{" "}
                  <code className="rounded-md bg-zinc-100 px-1.5 py-0.5 font-mono font-semibold text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
                    {prefix}
                  </code>{" "}
                  的活跃隧道。一旦客户端使用该前缀连接，此页面会自动恢复预览（
                  {sseState === "connected" ? "SSE 实时监听中" : "每 3 秒自动检测"}
                  ）。
                </p>

                <div className="mt-5 flex flex-wrap items-center justify-center gap-2.5">
                  <button
                    type="button"
                    onClick={handleRetryOnline}
                    disabled={isChecking}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-4 py-2 text-xs font-semibold text-zinc-950 shadow-xs transition hover:brightness-110 disabled:opacity-60"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${isChecking ? "animate-spin" : ""}`}
                    />
                    重新检测连接
                  </button>
                  <Link
                    href="/"
                    className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-xs font-medium text-zinc-700 transition hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-200 dark:hover:bg-zinc-800"
                  >
                    <ArrowLeft className="h-3.5 w-3.5" />
                    返回主控制台
                  </Link>
                </div>
              </div>

              <QuickStartCli
                info={info}
                adminToken={adminToken}
                initialSubdomain={prefix}
                compact
                title={`使用前缀 “${prefix}” 启动隧道`}
                subtitle="在本地终端执行以下命令上线后，本预览页会自动加载您的内网网站。"
              />
            </div>
          </div>
        )}
      </main>

      {/* Bottom Live Request Log Drawer */}
      {drawerOpen && (
        <aside
          aria-label="当前隧道实时请求日志"
          className={`flex shrink-0 flex-col border-t border-zinc-200 bg-white shadow-2xl transition-all dark:border-zinc-800 dark:bg-zinc-950 ${
            drawerExpanded ? "h-[48vh]" : "h-64"
          }`}
        >
          <div className="flex items-center justify-between border-b border-zinc-200/80 bg-zinc-50 px-3.5 py-1.5 text-[11px] dark:border-zinc-800/80 dark:bg-zinc-900/70">
            <div className="flex items-center gap-2 text-zinc-600 dark:text-zinc-300">
              <span className="font-mono font-semibold text-cyan-600 dark:text-cyan-400">
                {prefix}
              </span>
              <span>实时日志抽屉</span>
              <span className="text-zinc-400 dark:text-zinc-500">
                · 点击任意请求可展开详情并跳转预览路径
              </span>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setDrawerExpanded((e) => !e)}
                className="rounded-md p-1 text-zinc-500 hover:bg-zinc-200/70 hover:text-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
                title={drawerExpanded ? "还原高度" : "展开更高视图"}
              >
                {drawerExpanded ? (
                  <Minimize2 className="h-3.5 w-3.5" />
                ) : (
                  <Maximize2 className="h-3.5 w-3.5" />
                )}
              </button>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="rounded-md p-1 text-zinc-500 hover:bg-zinc-200/70 hover:text-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
                title="关闭日志抽屉"
              >
                <PanelBottomClose className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            <TrafficInspector
              logs={logs}
              compact
              lockedPrefix={prefix}
              onNavigatePath={(path) => navigateToSubPath(path)}
            />
          </div>
        </aside>
      )}
    </div>
  );
}
