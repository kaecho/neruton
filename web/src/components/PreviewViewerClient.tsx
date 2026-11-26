"use client";

import React, { useCallback, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowRight,
  ExternalLink,
  Laptop,
  Maximize2,
  Minimize2,
  PanelBottom,
  PanelBottomClose,
  RefreshCw,
  RotateCw,
  Smartphone,
  Tablet,
} from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { StatusDot } from "@/components/GeistPrimitives";
import { QuickStartCli } from "@/components/QuickStartCli";
import { useNerutonStream } from "@/hooks/useNerutonStream";
import { ApiError, fetchTunnel, resolveWildcardUrl } from "@/lib/api";
import { formatDurationMs } from "@/lib/format";
import type { TunnelInfo, ViewportMode } from "@/lib/types";

const TrafficInspector = dynamic(
  () =>
    import("@/components/TrafficInspector").then((m) => m.TrafficInspector),
  { ssr: false },
);

interface PreviewViewerClientProps {
  prefix: string;
}

const VIEWPORT_MODES = [
  { id: "desktop" as const, icon: Laptop, label: "桌面端 (100%)" },
  { id: "tablet" as const, icon: Tablet, label: "平板 (768px)" },
  { id: "mobile" as const, icon: Smartphone, label: "手机 (390px)" },
];

function normalizeSubPath(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

export function PreviewViewerClient({ prefix }: PreviewViewerClientProps) {
  const { handleUnauthorized } = useAuth();
  const { info, tunnels, logs, sseState, isLoading, refresh } =
    useNerutonStream({
      enabled: true,
      prefixFilter: prefix,
      onUnauthorized: handleUnauthorized,
    });

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

  const checkDirectTunnel = useCallback(async () => {
    setIsChecking(true);
    try {
      const found = await fetchTunnel(prefix);
      setDirectTunnel(found);
    } catch (err) {
      if (err instanceof ApiError && err.unauthorized) {
        handleUnauthorized();
      }
    } finally {
      setTunnelChecked(true);
      setIsChecking(false);
    }
  }, [prefix, handleUnauthorized]);

  useEffect(() => {
    void checkDirectTunnel();
  }, [checkDirectTunnel]);

  // Derived purely during render (no derived-state useEffect)
  const streamTunnel = tunnels.find((t) => t.prefix === prefix) ?? null;
  const activeTunnel = isLoading ? (streamTunnel ?? directTunnel) : streamTunnel;
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
        ? "h-full w-full max-w-[768px] border-x border-t border-border"
        : "h-full w-full max-w-[390px] border-x border-t border-border";

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-background text-foreground">
      {/* Compact Vercel Viewer Toolbar */}
      <header className="z-20 shrink-0 border-b border-border bg-background px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          {/* Left: Back + Prefix Status */}
          <div className="flex items-center gap-2">
            <Link
              href="/"
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-background px-2.5 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
            >
              <ArrowLeft className="h-3.5 w-3.5 text-secondary" />
              <span className="hidden sm:inline">概览</span>
            </Link>

            <div className="flex h-8 items-center gap-2 rounded-md border border-border bg-surface px-2.5">
              <StatusDot
                tone={
                  isOnline
                    ? "online"
                    : isInitialChecking
                      ? "muted"
                      : "error"
                }
              />
              <span
                className="max-w-[140px] truncate font-mono text-xs font-medium text-foreground"
                title={prefix}
              >
                {prefix}
              </span>
              {activeTunnel ? (
                <span className="hidden font-mono text-[11px] tabular-nums text-tertiary xl:inline">
                  {formatDurationMs(activeTunnel.latency_ms)}
                </span>
              ) : null}
            </div>
          </div>

          {/* Center: Monospace Sub-Path Address Bar */}
          <form
            onSubmit={handleAddressSubmit}
            className="order-last flex min-w-0 flex-1 basis-full items-center gap-1.5 md:order-none md:basis-auto"
          >
            <button
              type="button"
              onClick={handleReload}
              disabled={!isOnline}
              title="重新加载预览"
              aria-label="重新加载预览"
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-background text-secondary transition-colors hover:border-border-strong hover:text-foreground disabled:opacity-40"
            >
              <RotateCw
                className={`h-3.5 w-3.5 ${iframeLoading && isOnline ? "animate-spin" : ""}`}
              />
            </button>

            <div className="flex h-8 min-w-0 flex-1 items-center overflow-hidden rounded-md border border-border bg-background focus-within:border-foreground">
              <span
                className="shrink-0 select-none border-r border-border bg-surface px-2.5 py-1.5 font-mono text-[11px] text-secondary"
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
                placeholder="/"
                aria-label="子路径地址"
                className="min-w-0 flex-1 bg-transparent px-2.5 font-mono text-xs text-foreground placeholder:text-tertiary focus:outline-none"
              />
              <button
                type="submit"
                disabled={!isOnline}
                aria-label="跳转到路径"
                className="inline-flex h-full items-center border-l border-border bg-surface px-2.5 text-secondary transition-colors hover:text-foreground disabled:opacity-40"
              >
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </form>

          {/* Right: Viewport Switcher + External Links + Log Drawer Toggle */}
          <div className="ml-auto flex items-center gap-1.5">
            <div
              className="hidden h-8 items-center rounded-md border border-border bg-surface p-0.5 sm:inline-flex"
              role="group"
              aria-label="切换预览宽度"
            >
              {VIEWPORT_MODES.map((item) => {
                const Icon = item.icon;
                const active = viewport === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setViewport(item.id)}
                    title={item.label}
                    aria-label={item.label}
                    aria-pressed={active}
                    className={`inline-flex h-full items-center justify-center rounded px-2 transition-colors ${
                      active
                        ? "bg-background text-foreground"
                        : "text-secondary hover:text-foreground"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                  </button>
                );
              })}
            </div>

            <a
              href={wildcardUrl}
              target="_blank"
              rel="noopener noreferrer"
              title={`打开泛域名: ${wildcardUrl}`}
              className="inline-flex h-8 items-center gap-1 rounded-md border border-border bg-background px-2.5 text-xs text-secondary transition-colors hover:border-border-strong hover:text-foreground"
            >
              <span className="hidden xl:inline">泛域名</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>

            <a
              href={baseIframePath}
              target="_blank"
              rel="noopener noreferrer"
              title={`直连路径代理: ${baseIframePath}`}
              className="inline-flex h-8 items-center gap-1 rounded-md border border-border bg-background px-2.5 font-mono text-xs text-secondary transition-colors hover:border-border-strong hover:text-foreground"
            >
              <span className="hidden xl:inline">/t/</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>

            <button
              type="button"
              onClick={() => setDrawerOpen((o) => !o)}
              className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors ${
                drawerOpen
                  ? "border-foreground bg-foreground text-background"
                  : "border-border bg-background text-foreground hover:border-border-strong"
              }`}
              title="切换实时请求日志抽屉"
            >
              {drawerOpen ? (
                <PanelBottomClose className="h-3.5 w-3.5" />
              ) : (
                <PanelBottom className="h-3.5 w-3.5" />
              )}
              <span className="hidden lg:inline">日志</span>
              <span
                className={`font-mono text-[11px] tabular-nums ${
                  drawerOpen ? "text-background/80" : "text-secondary"
                }`}
              >
                {logs.length}
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Iframe Stage */}
      <main className="relative flex min-h-0 flex-1 flex-col overflow-hidden bg-surface">
        {isInitialChecking ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 text-xs text-secondary">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-foreground" />
            <p>
              正在连接隧道 <span className="font-mono text-foreground">{prefix}</span>
            </p>
          </div>
        ) : isOnline ? (
          <div
            className={`relative flex min-h-0 flex-1 flex-col items-center overflow-hidden ${
              viewport === "desktop" ? "" : "px-4 pt-4"
            }`}
          >
            {viewport !== "desktop" ? (
              <div className="mb-2 flex items-center gap-2 font-mono text-[11px] text-secondary">
                <span>
                  {viewport === "tablet" ? "Tablet · 768px" : "Mobile · 390px"}
                </span>
                <span className="text-border-strong">/</span>
                <span className="max-w-[240px] truncate">
                  {activeTunnel?.target_url}
                </span>
              </div>
            ) : null}

            {iframeLoading ? (
              <div className="absolute inset-x-0 top-0 z-10 h-[2px] bg-border">
                <div className="h-full w-1/3 animate-pulse bg-foreground" />
              </div>
            ) : null}

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
          <div className="flex-1 overflow-y-auto px-4 py-12">
            <div className="mx-auto max-w-3xl space-y-6">
              <div className="rounded-lg border border-border bg-background p-6 text-center">
                <div className="inline-flex items-center gap-2 rounded-full border border-border bg-surface px-2.5 py-1 text-xs text-secondary">
                  <StatusDot tone="error" />
                  <span>隧道离线</span>
                </div>
                <h1 className="mt-3 text-base font-semibold tracking-tight text-foreground">
                  隧道当前未在线或不存在
                </h1>
                <p className="mt-1.5 text-xs text-secondary">
                  未找到前缀为{" "}
                  <code className="font-mono text-foreground">{prefix}</code>{" "}
                  的活跃隧道。客户端上线后页面将自动恢复预览（
                  {sseState === "connected" ? "SSE 实时监听中" : "轮询检测中"}）。
                </p>

                <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
                  <button
                    type="button"
                    onClick={() => void handleRetryOnline()}
                    disabled={isChecking}
                    className="inline-flex h-8 items-center gap-1.5 rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${isChecking ? "animate-spin" : ""}`}
                    />
                    <span>重新检测</span>
                  </button>
                  <Link
                    href="/"
                    className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-background px-4 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
                  >
                    <ArrowLeft className="h-3.5 w-3.5 text-secondary" />
                    <span>返回概览</span>
                  </Link>
                </div>
              </div>

              <QuickStartCli
                info={info}
                initialSubdomain={prefix}
                defaultOpen
                collapsible={false}
              />
            </div>
          </div>
        )}
      </main>

      {/* Collapsible Bottom Request Log Drawer */}
      {drawerOpen ? (
        <aside
          aria-label="当前隧道请求日志"
          className={`flex shrink-0 flex-col border-t border-border bg-background ${
            drawerExpanded ? "h-[48vh]" : "h-64"
          }`}
        >
          <div className="flex items-center justify-between border-b border-border bg-surface px-3 py-1.5 text-[11px]">
            <div className="flex items-center gap-2 text-secondary">
              <span className="font-mono font-medium text-foreground">
                {prefix}
              </span>
              <span>实时请求日志</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setDrawerExpanded((e) => !e)}
                title={drawerExpanded ? "还原高度" : "展开高度"}
                aria-label={drawerExpanded ? "还原高度" : "展开高度"}
                className="rounded p-1 text-secondary hover:bg-muted hover:text-foreground"
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
                title="关闭日志抽屉"
                aria-label="关闭日志抽屉"
                className="rounded p-1 text-secondary hover:bg-muted hover:text-foreground"
              >
                <PanelBottomClose className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            <TrafficInspector
              logs={logs}
              sseState={sseState}
              compact
              lockedPrefix={prefix}
              onNavigatePath={(path) => navigateToSubPath(path)}
            />
          </div>
        </aside>
      ) : null}
    </div>
  );
}
