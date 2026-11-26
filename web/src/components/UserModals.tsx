"use client";

import React, { useState } from "react";
import { ModalDialog } from "@/components/GeistPrimitives";
import { createUser, updateUser } from "@/lib/api";
import { validateUsername } from "@/lib/format";
import type { UserAdminView, UserRole } from "@/lib/types";

interface CreateUserModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (user: UserAdminView) => void;
}

export function CreateUserModal({
  open,
  onClose,
  onCreated,
}: CreateUserModalProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("user");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClose = () => {
    setUsername("");
    setPassword("");
    setRole("user");
    setError(null);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const userErr = validateUsername(username);
    if (userErr) {
      setError(userErr);
      return;
    }
    if (password.length < 8) {
      setError("密码长度至少为 8 位");
      return;
    }

    setSubmitting(true);
    try {
      const created = await createUser({
        username: username.trim(),
        password,
        role,
      });
      onCreated(created);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建用户失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalDialog
      open={open}
      onClose={handleClose}
      title="新建用户"
      description="为用户分配登录凭据与角色权限。"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1.5">
          <label
            htmlFor="new-user-name"
            className="block text-xs font-medium text-foreground"
          >
            用户名
          </label>
          <input
            id="new-user-name"
            type="text"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="例如 alice"
            className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
          <p className="text-[11px] text-tertiary">
            3-32 位字母、数字或 . _ -
          </p>
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="new-user-password"
            className="block text-xs font-medium text-foreground"
          >
            初始密码
          </label>
          <input
            id="new-user-password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="至少 8 位字符"
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="new-user-role"
            className="block text-xs font-medium text-foreground"
          >
            角色
          </label>
          <select
            id="new-user-role"
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground focus:border-foreground focus:outline-none"
          >
            <option value="user">user（普通用户，仅管理自身隧道与令牌）</option>
            <option value="admin">admin（管理员，完整网关控制权限）</option>
          </select>
        </div>

        {error ? (
          <div
            role="alert"
            className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400"
          >
            {error}
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2 border-t border-border pt-4">
          <button
            type="button"
            onClick={handleClose}
            className="inline-flex h-8 items-center rounded-md border border-border bg-background px-3 text-xs text-secondary hover:text-foreground"
          >
            取消
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? "创建中..." : "创建用户"}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}

interface ResetPasswordModalProps {
  target: UserAdminView | null;
  onClose: () => void;
  onUpdated: (user: UserAdminView) => void;
}

export function ResetPasswordModal({
  target,
  onClose,
  onUpdated,
}: ResetPasswordModalProps) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClose = () => {
    setPassword("");
    setConfirm("");
    setError(null);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    setError(null);

    if (password.length < 8) {
      setError("新密码长度至少为 8 位");
      return;
    }
    if (password !== confirm) {
      setError("两次输入的密码不一致");
      return;
    }

    setSubmitting(true);
    try {
      const updated = await updateUser(target.id, { password });
      onUpdated(updated);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "重置密码失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalDialog
      open={Boolean(target)}
      onClose={handleClose}
      title={target ? `重置密码 · ${target.username}` : "重置密码"}
      description="重置后该用户的现有登录会话将自动失效。"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1.5">
          <label
            htmlFor="reset-user-password"
            className="block text-xs font-medium text-foreground"
          >
            新密码
          </label>
          <input
            id="reset-user-password"
            type="password"
            autoFocus
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="至少 8 位字符"
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="reset-user-confirm"
            className="block text-xs font-medium text-foreground"
          >
            确认新密码
          </label>
          <input
            id="reset-user-confirm"
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="再次输入新密码"
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
        </div>

        {error ? (
          <div
            role="alert"
            className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400"
          >
            {error}
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2 border-t border-border pt-4">
          <button
            type="button"
            onClick={handleClose}
            className="inline-flex h-8 items-center rounded-md border border-border bg-background px-3 text-xs text-secondary hover:text-foreground"
          >
            取消
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? "保存中..." : "确认重置"}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}
