"use client";

import React, { useCallback, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { Plus } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { StatusDot, Switch } from "@/components/GeistPrimitives";
import { useSharedStream } from "@/components/StreamContext";
import {
  ApiError,
  deleteToken,
  fetchSettings,
  fetchTokens,
  updateToken,
} from "@/lib/api";
import { formatRelativeTime, formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import type {
  CreateTokenResponse,
  SettingsResponse,
  TokenSummary,
} from "@/lib/types";

const CreateTokenModal = dynamic(
  () =>
    import("@/components/CreateTokenModal").then((m) => m.CreateTokenModal),
  { ssr: false },
);

export default function TokensPage() {
  const { locale, messages } = useI18n();
  const { user, handleUnauthorized } = useAuth();
  const { info, refresh: refreshStream } = useSharedStream();

  const [tokens, setTokens] = useState<TokenSummary[]>([]);
  const [settings, setSettings] = useState<SettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const isAdmin = user?.role === "admin";

  const loadData = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [tokenList, settingsData] = await Promise.all([
          fetchTokens(signal),
          fetchSettings(signal),
        ]);
        setTokens(tokenList);
        setSettings(settingsData);
        setError(null);
      } catch (err) {
        if (signal?.aborted) return;
        if (err instanceof ApiError && err.unauthorized) {
          handleUnauthorized();
          return;
        }
        setError(
          err instanceof Error && err.message
            ? err.message
            : messages.tokens.loadFailed,
        );
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [handleUnauthorized, messages.tokens.loadFailed],
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadData(controller.signal);
    return () => controller.abort();
  }, [loadData]);

  const requireAuth =
    settings?.require_tunnel_auth ??
    info?.require_tunnel_auth ??
    info?.auth_required ??
    true;

  const handleCreated = useCallback((created: CreateTokenResponse) => {
    setTokens((prev) => [created.token, ...prev]);
  }, []);

  const handleToggleEnabled = async (token: TokenSummary) => {
    setBusyId(token.id);
    setError(null);
    try {
      const updated = await updateToken(token.id, { enabled: !token.enabled });
      setTokens((prev) =>
        prev.map((item) => (item.id === updated.id ? updated : item)),
      );
      if (!updated.enabled) {
        void refreshStream();
      }
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.tokens.updateFailed,
      );
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await deleteToken(id);
      setTokens((prev) => prev.filter((item) => item.id !== id));
      setConfirmDeleteId(null);
      void refreshStream();
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.tokens.revokeFailed,
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            {messages.tokens.title}
          </h1>
          <p className="mt-1 text-xs text-secondary">
            {messages.tokens.subtitle}
          </p>
        </div>

        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-foreground px-3.5 text-xs font-medium text-background transition-opacity hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>{messages.tokens.createButton}</span>
        </button>
      </div>

      {/* Tunnel Auth Policy Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface px-4 py-3">
        <div className="flex items-center gap-2.5 text-xs">
          <StatusDot tone={requireAuth ? "online" : "warn"} />
          <span className="font-medium text-foreground">
            {requireAuth
              ? messages.tokens.policyEnforcedTitle
              : messages.tokens.policyOpenTitle}
          </span>
          <span className="text-secondary">
            {requireAuth
              ? messages.tokens.policyEnforcedDesc
              : messages.tokens.policyOpenDesc}
          </span>
        </div>
        {isAdmin ? (
          <Link
            href="/settings"
            className="text-xs font-medium text-foreground underline-offset-4 hover:underline"
          >
            {messages.tokens.policySettingsLink}
          </Link>
        ) : null}
      </div>

      {error ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2.5 text-xs text-red-600 dark:text-red-400"
        >
          {error}
        </div>
      ) : null}

      {/* Tokens Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-background">
        {loading ? (
          <div className="px-4 py-12 text-center text-xs text-secondary">
            {messages.tokens.loading}
          </div>
        ) : tokens.length === 0 ? (
          <div className="px-4 py-12 text-center">
            <p className="text-xs font-medium text-foreground">
              {messages.tokens.emptyTitle}
            </p>
            <p className="mt-1 text-xs text-secondary">
              {messages.tokens.emptyDesc}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[780px] border-collapse text-left">
              <thead className="border-b border-border bg-surface text-[11px] font-medium text-secondary">
                <tr>
                  <th className="py-2.5 pl-4 pr-3">
                    {messages.tokens.colName}
                  </th>
                  <th className="px-3 py-2.5">
                    {messages.tokens.colKeyPrefix}
                  </th>
                  {isAdmin ? (
                    <th className="px-3 py-2.5">{messages.tokens.colOwner}</th>
                  ) : null}
                  <th className="px-3 py-2.5">
                    {messages.tokens.colAllowedPrefixes}
                  </th>
                  <th className="px-3 py-2.5">
                    {messages.tokens.colLastUsed}
                  </th>
                  <th className="px-3 py-2.5">
                    {messages.tokens.colCreated}
                  </th>
                  <th className="px-3 py-2.5">{messages.tokens.colState}</th>
                  <th className="py-2.5 pl-3 pr-4 text-right">
                    {messages.tokens.colActions}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {tokens.map((token) => {
                  const isBusy = busyId === token.id;
                  const isConfirming = confirmDeleteId === token.id;
                  return (
                    <tr
                      key={token.id}
                      className="transition-colors hover:bg-surface"
                    >
                      <td className="whitespace-nowrap py-3 pl-4 pr-3 text-xs font-medium text-foreground">
                        {token.name}
                      </td>
                      <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-secondary">
                        {token.token_prefix}
                      </td>
                      {isAdmin ? (
                        <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-secondary">
                          {token.owner_username}
                        </td>
                      ) : null}
                      <td className="px-3 py-3">
                        {token.allowed_prefixes.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {token.allowed_prefixes.map((prefix) => (
                              <span
                                key={prefix}
                                className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[11px] text-foreground"
                              >
                                {prefix}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-xs text-tertiary">
                            {messages.common.unlimited}
                          </span>
                        )}
                      </td>
                      <td
                        className="whitespace-nowrap px-3 py-3 text-xs tabular-nums text-secondary"
                        title={
                          token.last_used_at
                            ? formatShortDate(token.last_used_at)
                            : undefined
                        }
                      >
                        {formatRelativeTime(token.last_used_at, locale)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-3 font-mono text-[11px] tabular-nums text-secondary">
                        {formatShortDate(token.created_at)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-3">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={token.enabled}
                            disabled={isBusy}
                            label={messages.tokens.toggleAria(token.name)}
                            onChange={() => void handleToggleEnabled(token)}
                          />
                          <span className="text-xs text-secondary">
                            {token.enabled
                              ? messages.common.enabled
                              : messages.common.disabled}
                          </span>
                        </div>
                      </td>
                      <td className="whitespace-nowrap py-3 pl-3 pr-4 text-right">
                        {isConfirming ? (
                          <div className="inline-flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleDelete(token.id)}
                              className="inline-flex h-7 items-center rounded-md bg-red-600 px-2.5 text-[11px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
                            >
                              {isBusy
                                ? messages.common.deleting
                                : messages.tokens.confirmRevoke}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => setConfirmDeleteId(null)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2 text-[11px] text-secondary hover:text-foreground"
                            >
                              {messages.common.cancel}
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => setConfirmDeleteId(token.id)}
                            className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-red-500/40 hover:text-red-600 disabled:opacity-40 dark:hover:text-red-400"
                          >
                            {messages.tokens.revoke}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {createOpen ? (
        <CreateTokenModal
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          info={info}
          onCreated={handleCreated}
        />
      ) : null}
    </div>
  );
}
