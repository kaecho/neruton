"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Radio,
  Search,
  Terminal,
  X,
} from "lucide-react";
import { AdminTokenModal } from "@/components/AdminTokenModal";
import { Header } from "@/components/Header";
import { KpiStatsRow } from "@/components/KpiStatsRow";
import { QuickStartCli } from "@/components/QuickStartCli";
import { TrafficInspector } from "@/components/TrafficInspector";
import { TunnelCard } from "@/components/TunnelCard";
import { useNerutonStream } from "@/hooks/useNerutonStream";
import {
  ApiError,
  disconnectTunnel,
  getStoredAdminToken,
  setStoredAdminToken,
} from "@/lib/api";

interface ToastMessage {
  id: number;
  tone: "success" | "error" | "info";
  text: string;
}

export function DashboardClient() {
  const { info, tunnels, logs, sseState, isLoading, error, refresh } =
    useNerutonStream();

  const [adminToken, setAdminToken] = useState("");
  const [tokenModalOpen, setTokenModalOpen] = useState(false);
  const [tokenModalReason, setTokenModalReason] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [disconnectingPrefix, setDisconnectingPrefix] = useState<string | null>(
    null,
  );
  const [showCliPanel, setShowCliPanel] = useState(false);
  const [tunnelSearch, setTunnelSearch] = useState("");
  const [selectedLogPrefix, setSelectedLogPrefix] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const trafficRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setAdminToken(getStoredAdminToken());
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const showToast = useCallback(
    (tone: ToastMessage["tone"], text: string) => {
      const id = Date.now();
      setToast({ id, tone, text });
      setTimeout(() => {
        setToast((prev) => (prev?.id === id ? null : prev));
      }, 3600);
    },
    [],
  );

  const handleSaveToken = useCallback(
    (nextToken: string) => {
      setAdminToken(nextToken);
      setStoredAdminToken(nextToken);
      setTokenModalReason(null);
      showToast(
        "info",
        nextToken ? "管理员令牌已保存至本地浏览器" : "已清除本地保存的管理员令牌",
      );
    },
    [showToast],
  );

  const handleManualRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      await refresh();
    } finally {
      setTimeout(() => setIsRefreshing(false), 350);
    }
  }, [refresh]);

  const handleDisconnect = useCallback(
    async (prefix: string) => {
      setDisconnectingPrefix(prefix);
      try {
        await disconnectTunnel(prefix, adminToken);
        showToast("success", `已断开隧道 ${prefix}`);
        await refresh();
      } catch (err) {
        if (err instanceof ApiError && err.unauthorized) {
          setTokenModalReason(
            `断开隧道 “${prefix}” 需要有效的管理员访问令牌 (HTTP ${err.status})，请先输入正确的 NERUTON_AUTH_TOKEN。`,
          );
          setTokenModalOpen(true);
        } else {
          const msg = err instanceof Error ? err.message : "断开隧道失败";
          showToast("error", `断开失败: ${msg}`);
        }
      } finally {
        setDisconnectingPrefix(null);
      }
    },
    [adminToken, refresh, showToast],
  );

  const handleFilterLogs = useCallback((prefix: string) => {
    setSelectedLogPrefix(prefix);
    trafficRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const filteredTunnels = useMemo(() => {
    const q = tunnelSearch.trim().toLowerCase();
    if (!q) return tunnels;
    return tunnels.filter(
      (t) =>
        t.prefix.toLowerCase().includes(q) ||
        t.target_url.toLowerCase().includes(q) ||
        t.client_os.toLowerCase().includes(q) ||
        t.remote_addr.toLowerCase().includes(q),
    );
  }, [tunnels, tunnelSearch]);

  return (
    <div className="neruton-grid-bg flex min-h-screen flex-col">
      <Header
        info={info}
        sseState={error && !info ? "error" : sseState}
        hasToken={Boolean(adminToken)}
        isRefreshing={isRefreshing}
        onRefresh={handleManualRefresh}
        onOpenTokenModal={() => {
          setTokenModalReason(null);
          setTokenModalOpen(true);
        }}
      />

      <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 sm:px-6">
        {/* Error Banner */}
        {error && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-rose-500/35 bg-rose-500/10 px-4 py-3 text-xs text-rose-700 dark:text-rose-300">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>
                无法获取网关实时数据：{error}。系统正在自动重试，请确认{" "}
                <code className="rounded bg-rose-500/15 px-1 py-0.5 font-mono">
                  neruton-server
                </code>{" "}
                正在运行。
              </span>
            </div>
            <button
              type="button"
              onClick={handleManualRefresh}
              className="rounded-lg bg-rose-500/20 px-3 py-1 font-medium transition hover:bg-rose-500/30"
            >
              立即重试
            </button>
          </div>
        )}

        {/* KPI Stats Row */}
        <KpiStatsRow info={info} tunnels={tunnels} isLoading={isLoading} />

        {/* Active Tunnels Section */}
        <section aria-label="活跃隧道列表" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <h1 className="text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">
                活跃隧道 Active Tunnels
              </h1>
              <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-0.5 font-mono text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                {tunnels.length}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {tunnels.length > 0 && (
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
                  <input
                    type="text"
                    value={tunnelSearch}
                    onChange={(e) => setTunnelSearch(e.target.value)}
                    placeholder="过滤前缀 / 本地地址..."
                    className="w-44 rounded-xl border border-zinc-200 bg-white/90 py-1.5 pl-8 pr-7 text-xs text-zinc-800 placeholder:text-zinc-400 focus:border-cyan-500 focus:outline-none sm:w-56 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-100"
                  />
                  {tunnelSearch && (
                    <button
                      type="button"
                      onClick={() => setTunnelSearch("")}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              )}

              {tunnels.length > 0 && (
                <button
                  type="button"
                  onClick={() => setShowCliPanel((v) => !v)}
                  className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition ${
                    showCliPanel
                      ? "border-cyan-500/50 bg-cyan-500/12 text-cyan-700 dark:text-cyan-300"
                      : "border-zinc-200 bg-white/90 text-zinc-700 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-200 dark:hover:bg-zinc-800"
                  }`}
                >
                  <Terminal className="h-3.5 w-3.5" />
                  接入新隧道 (CLI)
                  {showCliPanel ? (
                    <ChevronUp className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5" />
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Collapsible CLI Generator when tunnels exist */}
          {tunnels.length > 0 && showCliPanel && (
            <QuickStartCli info={info} adminToken={adminToken} />
          )}

          {/* Tunnel Cards Grid or Empty State with Interactive CLI Generator */}
          {isLoading && tunnels.length === 0 ? (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {[0, 1].map((idx) => (
                <div
                  key={idx}
                  className="h-56 animate-pulse rounded-2xl border border-zinc-200/80 bg-white/60 p-5 dark:border-zinc-800/80 dark:bg-zinc-900/50"
                >
                  <div className="h-5 w-40 rounded-lg bg-zinc-200 dark:bg-zinc-800" />
                  <div className="mt-4 h-9 w-full rounded-xl bg-zinc-200/70 dark:bg-zinc-800/70" />
                  <div className="mt-3 h-20 w-full rounded-xl bg-zinc-100 dark:bg-zinc-950/80" />
                </div>
              ))}
            </div>
          ) : tunnels.length === 0 ? (
            <div className="space-y-4">
              <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-zinc-300/90 bg-white/70 px-6 py-8 text-center backdrop-blur-sm dark:border-zinc-800 dark:bg-zinc-900/45">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/15 to-emerald-500/15 text-cyan-600 dark:text-cyan-400">
                  <Radio className="h-6 w-6" />
                </div>
                <h2 className="mt-3 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  当前没有在线的内网隧道
                </h2>
                <p className="mt-1 max-w-lg text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
                  使用下方交互式 CLI 命令生成器，在你的本地开发机或内网服务器执行{" "}
                  <code className="rounded bg-zinc-100 px-1 py-0.5 font-mono text-[11px] dark:bg-zinc-800">
                    neruton tunnel
                  </code>{" "}
                  即可瞬间获得泛域名地址与免域名 Web 内嵌预览入口。
                </p>
              </div>
              <QuickStartCli
                info={info}
                adminToken={adminToken}
                title="快速接入第一条隧道 · CLI Quick Start"
                subtitle="自动生成 UUID 前缀或指定自定义子域名，连接成功后本页将通过 SSE 自动上线显示。"
              />
            </div>
          ) : filteredTunnels.length === 0 ? (
            <div className="rounded-2xl border border-zinc-200/80 bg-white/75 p-8 text-center text-xs text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-900/50 dark:text-zinc-400">
              未找到匹配 “{tunnelSearch}” 的活跃隧道。
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {filteredTunnels.map((tunnel) => (
                <TunnelCard
                  key={tunnel.id || tunnel.prefix}
                  tunnel={tunnel}
                  info={info}
                  nowMs={nowMs}
                  isDisconnecting={disconnectingPrefix === tunnel.prefix}
                  onDisconnect={handleDisconnect}
                  onFilterLogs={handleFilterLogs}
                />
              ))}
            </div>
          )}
        </section>

        {/* Live Traffic Inspector */}
        <div ref={trafficRef} className="scroll-mt-20">
          <TrafficInspector
            logs={logs}
            tunnels={tunnels}
            selectedPrefix={selectedLogPrefix}
            onSelectedPrefixChange={setSelectedLogPrefix}
          />
        </div>
      </main>

      <footer className="border-t border-zinc-200/70 py-4 text-center text-[11px] text-zinc-400 dark:border-zinc-800/70 dark:text-zinc-500">
        Neruton Self-Hosted Tunnel Gateway · Yamux over WebSocket · Wildcard &amp; Embedded Web Proxy
      </footer>

      {/* Admin Token Modal */}
      <AdminTokenModal
        open={tokenModalOpen}
        token={adminToken}
        authRequired={Boolean(info?.auth_required)}
        reason={tokenModalReason}
        onSave={handleSaveToken}
        onClose={() => setTokenModalOpen(false)}
      />

      {/* Toast Notification */}
      {toast && (
        <div
          role="status"
          className={`fixed bottom-5 right-5 z-50 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-xs font-medium shadow-lg backdrop-blur-md ${
            toast.tone === "success"
              ? "border-emerald-500/40 bg-emerald-950/90 text-emerald-200"
              : toast.tone === "error"
                ? "border-rose-500/40 bg-rose-950/90 text-rose-200"
                : "border-cyan-500/40 bg-zinc-900/95 text-cyan-200"
          }`}
        >
          <span>{toast.text}</span>
          <button
            type="button"
            onClick={() => setToast(null)}
            className="ml-1 opacity-70 hover:opacity-100"
            aria-label="关闭通知"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
