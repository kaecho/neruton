"use client";

import React, { memo, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  ExternalLink,
  Monitor,
  RefreshCw,
} from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { CopyButton, StatusDot } from "@/components/GeistPrimitives";
import { QuickStartCli } from "@/components/QuickStartCli";
import { useSharedStream } from "@/components/StreamContext";
import { STREAM_CONNECTION_ERROR } from "@/hooks/useNerutonStream";
import {
  disconnectTunnel,
  fetchSettings,
  resolveWildcardUrl,
} from "@/lib/api";
import {
  formatBytes,
  formatClockTime,
  formatDurationMs,
  formatNumber,
  formatUptime,
  isUuidLike,
} from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import type { ServerInfo, TunnelInfo } from "@/lib/types";

interface TunnelRowProps {
  tunnel: TunnelInfo;
  info: ServerInfo | null;
  confirming: boolean;
  disconnecting: boolean;
  onStartConfirm: (prefix: string) => void;
  onCancelConfirm: () => void;
  onConfirmDisconnect: (prefix: string) => void;
}

const TunnelRow = memo(function TunnelRow({
  tunnel,
  info,
  confirming,
  disconnecting,
  onStartConfirm,
  onCancelConfirm,
  onConfirmDisconnect,
}: TunnelRowProps) {
  const { locale, messages } = useI18n();
  const wildcardUrl = resolveWildcardUrl(tunnel.prefix, info, tunnel);
  const displayHost = wildcardUrl.replace(/^https?:\/\//, "");
  const isUuid = isUuidLike(tunnel.prefix);
  const totalBytes = (tunnel.bytes_in || 0) + (tunnel.bytes_out || 0);
  const ownerLabel = tunnel.owner_username
    ? tunnel.token_name
      ? `${tunnel.owner_username} / ${tunnel.token_name}`
      : tunnel.owner_username
    : tunnel.token_name || messages.common.anonymous;

  return (
    <tr className="transition-colors hover:bg-surface">
      {/* Prefix */}
      <td className="whitespace-nowrap py-3 pl-4 pr-3">
        <div className="flex items-center gap-2">
          <span
            className="max-w-[160px] truncate font-mono text-xs font-medium text-foreground"
            title={tunnel.prefix}
          >
            {tunnel.prefix}
          </span>
          {isUuid ? (
            <span className="rounded border border-border bg-surface px-1 py-0.5 font-mono text-[10px] text-tertiary">
              UUID
            </span>
          ) : null}
        </div>
      </td>

      {/* Wildcard URL */}
      <td className="whitespace-nowrap px-3 py-3">
        <div className="flex items-center gap-1.5">
          <a
            href={wildcardUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex max-w-[210px] items-center gap-1 truncate font-mono text-xs text-foreground underline-offset-4 hover:underline"
            title={wildcardUrl}
          >
            <span className="truncate">{displayHost}</span>
            <ExternalLink className="h-3 w-3 shrink-0 text-tertiary" />
          </a>
          <CopyButton
            text={wildcardUrl}
            label={messages.overview.copyWildcardUrl}
            iconOnly
            className="h-6 w-6"
          />
        </div>
      </td>

      {/* Target URL */}
      <td className="whitespace-nowrap px-3 py-3">
        <span
          className="inline-block max-w-[180px] truncate font-mono text-xs text-secondary"
          title={tunnel.target_url}
        >
          {tunnel.target_url}
        </span>
      </td>

      {/* Owner / Token */}
      <td className="whitespace-nowrap px-3 py-3">
        <span
          className="inline-block max-w-[150px] truncate text-xs text-secondary"
          title={ownerLabel}
        >
          {ownerLabel}
        </span>
      </td>

      {/* Latency */}
      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
        {formatDurationMs(tunnel.latency_ms)}
      </td>

      {/* Requests / Traffic */}
      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
        <span>{formatNumber(tunnel.requests_total, locale)}</span>
        <span className="mx-1 text-border-strong">/</span>
        <span>{formatBytes(totalBytes)}</span>
      </td>

      {/* Status */}
      <td className="whitespace-nowrap px-3 py-3">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2 py-0.5 text-[11px] text-foreground">
          <StatusDot tone="online" />
          <span>{messages.common.online}</span>
        </span>
      </td>

      {/* Actions */}
      <td className="whitespace-nowrap py-3 pl-3 pr-4 text-right">
        {confirming ? (
          <div className="inline-flex items-center justify-end gap-1.5">
            <button
              type="button"
              disabled={disconnecting}
              onClick={() => onConfirmDisconnect(tunnel.prefix)}
              className="inline-flex h-7 items-center rounded-md bg-red-600 px-2.5 text-[11px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {disconnecting
                ? messages.overview.disconnecting
                : messages.overview.confirmDisconnect}
            </button>
            <button
              type="button"
              disabled={disconnecting}
              onClick={onCancelConfirm}
              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2 text-[11px] text-secondary hover:text-foreground"
            >
              {messages.common.cancel}
            </button>
          </div>
        ) : (
          <div className="inline-flex items-center justify-end gap-1.5">
            <Link
              href={`/preview/${encodeURIComponent(tunnel.prefix)}`}
              className="inline-flex h-7 items-center gap-1 rounded-md border border-border bg-background px-2.5 text-[11px] font-medium text-foreground transition-colors hover:border-border-strong"
            >
              <Monitor className="h-3 w-3 text-secondary" />
              <span>{messages.overview.preview}</span>
            </Link>
            <button
              type="button"
              onClick={() => onStartConfirm(tunnel.prefix)}
              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-red-500/40 hover:text-red-600 dark:hover:text-red-400"
            >
              {messages.overview.disconnect}
            </button>
          </div>
        )}
      </td>
    </tr>
  );
});

export default function OverviewPage() {
  const { locale, messages } = useI18n();
  const { user } = useAuth();
  const {
    info,
    tunnels,
    logs,
    sseState,
    isLoading,
    error,
    refresh,
    removeTunnelLocal,
  } = useSharedStream();

  const [confirmPrefix, setConfirmPrefix] = useState<string | null>(null);
  const [disconnectingPrefix, setDisconnectingPrefix] = useState<string | null>(
    null,
  );
  const [actionError, setActionError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [reservedPrefixes, setReservedPrefixes] = useState<string[]>();

  useEffect(() => {
    const controller = new AbortController();
    fetchSettings(controller.signal)
      .then((res) => {
        setReservedPrefixes([
          ...res.default_reserved_prefixes,
          ...res.reserved_prefixes,
        ]);
      })
      .catch(() => {
        // Non-fatal fallback to client defaults
      });
    return () => controller.abort();
  }, []);

  const isAdmin = user?.role === "admin";
  const requireAuth = info
    ? (info.require_tunnel_auth ?? info.auth_required)
    : true;
  const recentLogs = logs.slice(0, 8);
  const resolvedStreamError =
    error === STREAM_CONNECTION_ERROR
      ? messages.overview.streamErrorFallback
      : error;

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refresh();
    } finally {
      setRefreshing(false);
    }
  };

  const handleStartConfirm = useCallback((prefix: string) => {
    setActionError(null);
    setConfirmPrefix(prefix);
  }, []);

  const handleCancelConfirm = useCallback(() => {
    setConfirmPrefix(null);
  }, []);

  const handleConfirmDisconnect = useCallback(
    async (prefix: string) => {
      setDisconnectingPrefix(prefix);
      setActionError(null);
      try {
        await disconnectTunnel(prefix);
        removeTunnelLocal(prefix);
        setConfirmPrefix(null);
      } catch (err) {
        setActionError(
          err instanceof Error && err.message
            ? err.message
            : messages.overview.disconnectFailed(prefix),
        );
      } finally {
        setDisconnectingPrefix(null);
      }
    },
    [removeTunnelLocal, messages],
  );

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            {messages.overview.title}
          </h1>
          <p className="mt-1 text-xs text-secondary">
            {messages.overview.subtitle}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-xs text-secondary">
            <StatusDot
              tone={
                sseState === "connected"
                  ? "online"
                  : sseState === "polling"
                    ? "warn"
                    : "muted"
              }
            />
            <span>
              {sseState === "connected"
                ? messages.overview.sseConnected
                : sseState === "polling"
                  ? messages.overview.ssePolling
                  : messages.overview.sseConnecting}
            </span>
          </div>
          <button
            type="button"
            onClick={() => void handleRefresh()}
            disabled={refreshing}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-background px-3 text-xs font-medium text-foreground transition-colors hover:border-border-strong disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-secondary ${refreshing ? "animate-spin" : ""}`}
            />
            <span>{messages.common.refresh}</span>
          </button>
        </div>
      </div>

      {/* Error banner */}
      {resolvedStreamError || actionError ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2.5 text-xs text-red-600 dark:text-red-400"
        >
          {actionError || resolvedStreamError}
        </div>
      ) : null}

      {/* 4-Column Hairline Metrics Strip */}
      <section
        aria-label={messages.overview.metricsAria}
        className="grid grid-cols-1 divide-y divide-border overflow-hidden rounded-lg border border-border bg-background sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x"
      >
        <div className="p-4 sm:border-b sm:border-r lg:border-b-0 lg:border-r-0">
          <div className="flex items-center justify-between text-xs text-secondary">
            <span>{messages.overview.activeTunnels}</span>
            <StatusDot tone={tunnels.length > 0 ? "online" : "muted"} />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tracking-tight tabular-nums text-foreground">
            {isLoading && !info ? "—" : formatNumber(tunnels.length, locale)}
          </div>
          <p className="mt-1 text-[11px] text-tertiary">
            {isAdmin
              ? messages.overview.activeTunnelsAdminSub
              : messages.overview.activeTunnelsUserSub}
          </p>
        </div>

        <div className="p-4 sm:border-b lg:border-b-0">
          <div className="text-xs text-secondary">
            {messages.overview.totalRequests}
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tracking-tight tabular-nums text-foreground">
            {info ? formatNumber(info.total_requests, locale) : "—"}
          </div>
          <p className="mt-1 text-[11px] text-tertiary">
            {messages.overview.totalRequestsSub}
          </p>
        </div>

        <div className="p-4 sm:border-r lg:border-r-0">
          <div className="flex items-center justify-between text-xs text-secondary">
            <span>{messages.overview.tunnelAuth}</span>
            <StatusDot tone={requireAuth ? "online" : "warn"} />
          </div>
          <div className="mt-2 text-lg font-semibold tracking-tight text-foreground">
            {info
              ? requireAuth
                ? messages.overview.authEnforced
                : messages.overview.authOpen
              : "—"}
          </div>
          <p className="mt-1 text-[11px] text-tertiary">
            <Link
              href={isAdmin ? "/settings" : "/tokens"}
              className="underline-offset-4 hover:text-foreground hover:underline"
            >
              {isAdmin
                ? messages.overview.managePolicy
                : messages.overview.manageMyTokens}
            </Link>
          </p>
        </div>

        <div className="p-4">
          <div className="text-xs text-secondary">
            {messages.overview.uptimeAndVersion}
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tracking-tight tabular-nums text-foreground">
            {info ? formatUptime(info.uptime_secs, locale) : "—"}
          </div>
          <p className="mt-1 font-mono text-[11px] text-tertiary">
            {info ? `neruton-server v${info.version}` : "—"}
          </p>
        </div>
      </section>

      {/* Active Tunnels Table */}
      <section aria-label={messages.overview.tunnelsSectionAria} className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold tracking-tight text-foreground">
              {messages.overview.activeTunnels}
            </h2>
            <span className="rounded-full border border-border bg-surface px-2 py-0.5 font-mono text-[11px] tabular-nums text-secondary">
              {tunnels.length}
            </span>
          </div>
          <Link
            href="/tokens"
            className="text-xs text-secondary underline-offset-4 hover:text-foreground hover:underline"
          >
            {messages.overview.manageTokensLink}
          </Link>
        </div>

        <div className="overflow-hidden rounded-lg border border-border bg-background">
          {isLoading && tunnels.length === 0 ? (
            <div className="px-4 py-12 text-center text-xs text-secondary">
              {messages.overview.loadingTunnels}
            </div>
          ) : tunnels.length === 0 ? (
            <div className="px-4 py-12 text-center">
              <p className="text-xs font-medium text-foreground">
                {messages.overview.emptyTunnelsTitle}
              </p>
              <p className="mt-1 text-xs text-secondary">
                {messages.overview.emptyTunnelsBefore}
                <code className="font-mono text-foreground">
                  neruton tunnel
                </code>
                {messages.overview.emptyTunnelsAfter}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] border-collapse text-left">
                <thead className="border-b border-border bg-surface text-[11px] font-medium text-secondary">
                  <tr>
                    <th className="py-2.5 pl-4 pr-3">
                      {messages.overview.colPrefix}
                    </th>
                    <th className="px-3 py-2.5">
                      {messages.overview.colWildcardUrl}
                    </th>
                    <th className="px-3 py-2.5">
                      {messages.overview.colTargetUrl}
                    </th>
                    <th className="px-3 py-2.5">
                      {messages.overview.colOwnerToken}
                    </th>
                    <th className="px-3 py-2.5 text-right">
                      {messages.overview.colLatency}
                    </th>
                    <th className="px-3 py-2.5 text-right">
                      {messages.overview.colReqTraffic}
                    </th>
                    <th className="px-3 py-2.5">
                      {messages.overview.colStatus}
                    </th>
                    <th className="py-2.5 pl-3 pr-4 text-right">
                      {messages.overview.colActions}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {tunnels.map((tunnel) => (
                    <TunnelRow
                      key={tunnel.id || tunnel.prefix}
                      tunnel={tunnel}
                      info={info}
                      confirming={confirmPrefix === tunnel.prefix}
                      disconnecting={disconnectingPrefix === tunnel.prefix}
                      onStartConfirm={handleStartConfirm}
                      onCancelConfirm={handleCancelConfirm}
                      onConfirmDisconnect={(prefix) =>
                        void handleConfirmDisconnect(prefix)
                      }
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* Collapsible Quick Connect CLI Panel */}
      <QuickStartCli
        info={info}
        reservedPrefixes={reservedPrefixes}
        defaultOpen={false}
        collapsible
      />

      {/* Recent Traffic Summary */}
      <section aria-label={messages.overview.recentTrafficAria} className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold tracking-tight text-foreground">
            {messages.overview.recentTraffic}
          </h2>
          <Link
            href="/logs"
            className="inline-flex items-center gap-1 text-xs text-secondary transition-colors hover:text-foreground"
          >
            <span>{messages.overview.viewAllLogs}</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        <div className="overflow-hidden rounded-lg border border-border bg-background">
          {recentLogs.length === 0 ? (
            <div className="px-4 py-10 text-center text-xs text-secondary">
              {messages.overview.noRequests}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] border-collapse text-left">
                <thead className="border-b border-border bg-surface text-[11px] font-medium text-secondary">
                  <tr>
                    <th className="py-2 pl-4 pr-3">
                      {messages.overview.colTime}
                    </th>
                    <th className="px-3 py-2">
                      {messages.overview.colMethod}
                    </th>
                    <th className="px-3 py-2">
                      {messages.overview.colStatus}
                    </th>
                    <th className="px-3 py-2">
                      {messages.overview.colTunnel}
                    </th>
                    <th className="px-3 py-2">{messages.overview.colPath}</th>
                    <th className="py-2 pl-3 pr-4 text-right">
                      {messages.overview.colDuration}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {recentLogs.map((log, idx) => (
                    <tr
                      key={log.id || `${log.timestamp}-${idx}`}
                      className="transition-colors hover:bg-surface"
                    >
                      <td className="whitespace-nowrap py-2 pl-4 pr-3 font-mono text-[11px] tabular-nums text-secondary">
                        {formatClockTime(log.timestamp)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <span className="inline-block rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground">
                          {log.method}
                        </span>
                      </td>
                      <td
                        className={`whitespace-nowrap px-3 py-2 font-mono text-xs font-medium tabular-nums ${
                          log.status >= 500
                            ? "text-red-600 dark:text-red-400"
                            : log.status >= 400
                              ? "text-amber-600 dark:text-amber-400"
                              : log.status >= 200 && log.status < 300
                                ? "text-emerald-600 dark:text-emerald-400"
                                : "text-secondary"
                        }`}
                      >
                        {log.status}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-secondary">
                        <Link
                          href={`/preview/${encodeURIComponent(log.tunnel_prefix)}`}
                          className="underline-offset-4 hover:text-foreground hover:underline"
                        >
                          {log.tunnel_prefix}
                        </Link>
                      </td>
                      <td
                        className="max-w-[300px] truncate px-3 py-2 font-mono text-xs text-foreground"
                        title={log.path}
                      >
                        {log.path}
                      </td>
                      <td className="whitespace-nowrap py-2 pl-3 pr-4 text-right font-mono text-[11px] tabular-nums text-secondary">
                        {formatDurationMs(log.duration_ms)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
