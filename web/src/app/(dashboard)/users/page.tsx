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
        setError(err instanceof Error ? err.message : "加载用户列表失败");
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [isAdmin, handleUnauthorized],
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
          无访问权限
        </h1>
        <p className="mt-1.5 text-xs text-secondary">
          用户管理页面仅对管理员开放。如需变更权限请联系系统管理员。
        </p>
        <Link
          href="/"
          className="mt-5 inline-flex h-8 items-center rounded-md border border-border bg-background px-3.5 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
        >
          返回概览
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
      setError(err instanceof Error ? err.message : "更新用户状态失败");
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
      setError(err instanceof Error ? err.message : "更新用户角色失败");
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
      setError(err instanceof Error ? err.message : "删除用户失败");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            用户管理
          </h1>
          <p className="mt-1 text-xs text-secondary">
            管理系统账户、角色权限与活跃状态；禁用或删除用户将立即断开其所有隧道。
          </p>
        </div>

        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-foreground px-3.5 text-xs font-medium text-background transition-opacity hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>新建用户</span>
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
            正在加载用户列表...
          </div>
        ) : users.length === 0 ? (
          <div className="px-4 py-12 text-center text-xs text-secondary">
            暂无用户记录
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] border-collapse text-left">
              <thead className="border-b border-border bg-surface text-[11px] font-medium text-secondary">
                <tr>
                  <th className="py-2.5 pl-4 pr-3">用户名</th>
                  <th className="px-3 py-2.5">角色</th>
                  <th className="px-3 py-2.5">状态</th>
                  <th className="px-3 py-2.5 text-right">令牌数</th>
                  <th className="px-3 py-2.5 text-right">活跃隧道</th>
                  <th className="px-3 py-2.5">最后登录</th>
                  <th className="px-3 py-2.5">创建时间</th>
                  <th className="py-2.5 pl-3 pr-4 text-right">操作</th>
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
                              当前
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
                            label={`切换用户 ${item.username} 启用状态`}
                            onChange={() => void handleToggleEnabled(item)}
                          />
                          <span className="inline-flex items-center gap-1.5 text-xs text-secondary">
                            <StatusDot tone={item.enabled ? "online" : "muted"} />
                            <span>{item.enabled ? "启用" : "禁用"}</span>
                          </span>
                        </div>
                      </td>

                      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
                        {formatNumber(item.token_count)}
                      </td>

                      <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-xs tabular-nums text-secondary">
                        {formatNumber(item.active_tunnel_count)}
                      </td>

                      <td
                        className="whitespace-nowrap px-3 py-3 text-xs tabular-nums text-secondary"
                        title={
                          item.last_login_at
                            ? formatShortDate(item.last_login_at)
                            : undefined
                        }
                      >
                        {formatRelativeTime(item.last_login_at)}
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
                              {isBusy ? "删除中..." : "确认删除"}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => setConfirmDeleteId(null)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2 text-[11px] text-secondary hover:text-foreground"
                            >
                              取消
                            </button>
                          </div>
                        ) : (
                          <div className="inline-flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              disabled={isBusy || isSelf}
                              onClick={() => void handleToggleRole(item)}
                              title={
                                isSelf ? "不可修改当前登录账户角色" : undefined
                              }
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-border-strong hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {item.role === "admin" ? "设为普通用户" : "设为管理员"}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => setResetTarget(item)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-border-strong hover:text-foreground disabled:opacity-40"
                            >
                              重置密码
                            </button>
                            <button
                              type="button"
                              disabled={isBusy || isSelf}
                              title={isSelf ? "不可删除当前登录账户" : undefined}
                              onClick={() => setConfirmDeleteId(item.id)}
                              className="inline-flex h-7 items-center rounded-md border border-border bg-background px-2.5 text-[11px] text-secondary transition-colors hover:border-red-500/40 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:text-red-400"
                            >
                              删除
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
