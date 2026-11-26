"use client";

import React, { useCallback, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { Plus } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { StatusDot, Switch } from "@/components/GeistPrimitives";
import { useSharedStream } from "@/components/StreamContext";
import { ApiError, deleteUser, fetchUsers, updateUser } from "@/lib/api";
import {
  formatNumber,
  formatRelativeTime,
  formatShortDate,
} from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import type { UserAdminView, UserRole } from "@/lib/types";

const CreateUserModal = dynamic(
  () => import("@/components/UserModals").then((m) => m.CreateUserModal),
  { ssr: false },
);

const ResetPasswordModal = dynamic(
  () => import("@/components/UserModals").then((m) => m.ResetPasswordModal),
  { ssr: false },
);

export default function UsersPage() {
  const { locale, messages } = useI18n();
  const { user: currentUser, handleUnauthorized } = useAuth();
  const { refresh: refreshStream } = useSharedStream();

  const isAdmin = currentUser?.role === "admin";

  const [users, setUsers] = useState<UserAdminView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [resetTarget, setResetTarget] = useState<UserAdminView | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const loadUsers = useCallback(
    async (signal?: AbortSignal) => {
      if (!isAdmin) {
        setLoading(false);
        return;
      }
      try {
        const list = await fetchUsers(signal);
        setUsers(list);
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
            : messages.users.loadFailed,
        );
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [isAdmin, handleUnauthorized, messages.users.loadFailed],
  );

  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    void loadUsers(controller.signal);
    return () => controller.abort();
  }, [isAdmin, loadUsers]);

  if (!isAdmin) {
    return (
      <div className="mx-auto max-w-md py-16 text-center">
        <p className="font-mono text-xs text-tertiary">403</p>
        <h1 className="mt-2 text-lg font-semibold tracking-tight text-foreground">
          {messages.users.forbiddenTitle}
        </h1>
        <p className="mt-1.5 text-xs text-secondary">
          {messages.users.forbiddenDesc}
        </p>
        <Link
          href="/"
          className="mt-5 inline-flex h-8 items-center rounded-md border border-border bg-background px-3.5 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
        >
          {messages.users.backToOverview}
        </Link>
      </div>
    );
  }

  const handleToggleEnabled = async (target: UserAdminView) => {
    setBusyId(target.id);
    setError(null);
    try {
      const updated = await updateUser(target.id, { enabled: !target.enabled });
      setUsers((prev) =>
        prev.map((item) => (item.id === updated.id ? updated : item)),
      );
      if (!updated.enabled) {
        void refreshStream();
      }
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.users.updateStatusFailed,
      );
    } finally {
      setBusyId(null);
    }
  };

  const handleToggleRole = async (target: UserAdminView) => {
    const nextRole: UserRole = target.role === "admin" ? "user" : "admin";
    setBusyId(target.id);
    setError(null);
    try {
      const updated = await updateUser(target.id, { role: nextRole });
      setUsers((prev) =>
        prev.map((item) => (item.id === updated.id ? updated : item)),
      );
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.users.updateRoleFailed,
      );
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await deleteUser(id);
      setUsers((prev) => prev.filter((item) => item.id !== id));
      setConfirmDeleteId(null);
      void refreshStream();
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.users.deleteFailed,
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            {messages.users.title}
          </h1>
          <p className="mt-1 text-xs text-secondary">
            {messages.users.subtitle}
          </p>
        </div>

        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-foreground px-3.5 text-xs font-medium text-background transition-opacity hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>{messages.users.createButton}</span>
        </button>
      </div>

      {error ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2.5 text-xs text-red-600 dark:text-red-400"
        >
          {error}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-lg border border-border bg-background">
        {loading ? (
          <div className="px-4 py-12 text-center text-xs text-secondary">
            {messages.users.loading}
          </div>
        ) : users.length === 0 ? (
          <div className="px-4 py-12 text-center text-xs text-secondary">
            {messages.users.empty}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] border-collapse text-left">
              <thead className="border-b border-border bg-surface text-[11px] font-medium text-secondary">
                <tr>
                  <th className="py-2.5 pl-4 pr-3">
                    {messages.users.colUsername}
                  </th>
                  <th className="px-3 py-2.5">{messages.users.colRole}</th>
                  <th className="px-3 py-2.5">{messages.users.colStatus}</th>
                  <th className="px-3 py-2.5 text-right">
                    {messages.users.colTokens}
                  </th>
                  <th className="px-3 py-2.5 text-right">
                    {messages.users.colActiveTunnels}
                  </th>
                  <th className="px-3 py-2.5">
                    {messages.users.colLastLogin}
                  </th>
                  <th className="px-3 py-2.5">{messages.users.colCreated}</th>
                  <th className="py-2.5 pl-3 pr-4 text-right">
                    {messages.users.colActions}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users.map((item) => {
                  const isSelf = item.id === currentUser?.id;
                  const isBusy = busyId === item.id;
                  const isConfirming = confirmDeleteId === item.id;

                  return (
                    <tr
                      key={item.id}
                      className="transition-colors hover:bg-surface"
                    >
                      <td className="whitespace-nowrap py-3 pl-4 pr-3">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-medium text-foreground">
                            {item.username}
                          </span>
                          {isSelf ? (
                            <span className="rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] text-secondary">
                              {messages.common.current}
                            </span>
                          ) : null}
                        </div>
                      </td>

                      <td className="whitespace-nowrap px-3 py-3">
                        <span
                          className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[11px] ${
                            item.role === "admin"
                              ? "border-foreground/30 bg-surface font-medium text-foreground"
                              : "border-border bg-background text-secondary"
                          }`}
                        >
                          {item.role}
                        </span>
                      </td>

                      <td className="whitespace-nowrap px-3 py-3">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={item.enabled}
                            disabled={isBusy || isSelf}
                            label={messages.users.toggleAria(item.username)}
                            onChange={() => void handleToggleEnabled(item)}
                          />
                          <span className="inline-flex items-center gap-1.5 text-xs text-secondary">
                            <StatusDot
                              tone={item.enabled ? "online" : "muted"}
                            />
                            <span>
                              {item.enabled
                                ? messages.common.enabled
                                : messages.common.disabled}
                            </span>
                          </span>
                        </div>
                      </td>

                      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
                        {formatNumber(item.token_count, locale)}
                      </td>

                      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
                        {formatNumber(item.active_tunnel_count, locale)}
                      </td>

                      <td
                        className="whitespace-nowrap px-3 py-3 text-xs tabular-nums text-secondary"
                        title={
                          item.last_login_at
                            ? formatShortDate(item.last_login_at)
                            : undefined
                        }
                      >
                        {formatRelativeTime(item.last_login_at, locale)}
                      </td>

                      <td className="whitespace-nowrap px-3 py-3 font-mono text-[11px] tabular-nums text-secondary">
                        {formatShortDate(item.created_at)}
                      </td>

                      <td className="whitespace-nowrap py-3 pl-3 pr-4 text-right">
                        {isConfirming ? (
                          <div className="inline-flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleDelete(item.id)}
                              className="inline-flex h-7 items-center rounded-md bg-red-600 px-2.5 text-[11px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
                            >
                              {isBusy
                                ? messages.common.deleting
                                : messages.users.confirmDelete}
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
                          <div className="inline-flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              disabled={isBusy || isSelf}
                              onClick={() => void handleToggleRole(item)}
                              title={
                                isSelf
                                  ? messages.users.cannotChangeOwnRole
                                  : undefined
                              }
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-border-strong hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {item.role === "admin"
                                ? messages.users.makeUser
                                : messages.users.makeAdmin}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => setResetTarget(item)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-border-strong hover:text-foreground disabled:opacity-40"
                            >
                              {messages.users.resetPassword}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy || isSelf}
                              title={
                                isSelf
                                  ? messages.users.cannotDeleteSelf
                                  : undefined
                              }
                              onClick={() => setConfirmDeleteId(item.id)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-red-500/40 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:text-red-400"
                            >
                              {messages.common.delete}
                            </button>
                          </div>
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
        <CreateUserModal
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          onCreated={(created) => setUsers((prev) => [...prev, created])}
        />
      ) : null}

      {resetTarget ? (
        <ResetPasswordModal
          target={resetTarget}
          onClose={() => setResetTarget(null)}
          onUpdated={(updated) =>
            setUsers((prev) =>
              prev.map((item) => (item.id === updated.id ? updated : item)),
            )
          }
        />
      ) : null}
    </div>
  );
}
