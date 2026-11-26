"use client";

import React, { useState } from "react";
import { ModalDialog } from "@/components/GeistPrimitives";
import { createUser, updateUser } from "@/lib/api";
import { validateUsername } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
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
  const { locale, messages } = useI18n();
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

    const userErr = validateUsername(username, locale);
    if (userErr) {
      setError(userErr);
      return;
    }
    if (password.length < 8) {
      setError(messages.auth.passwordMinError);
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
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.users.createFailed,
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalDialog
      open={open}
      onClose={handleClose}
      title={messages.users.createTitle}
      description={messages.users.createDesc}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1.5">
          <label
            htmlFor="new-user-name"
            className="block text-xs font-medium text-foreground"
          >
            {messages.auth.username}
          </label>
          <input
            id="new-user-name"
            type="text"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={messages.users.usernamePlaceholder}
            className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
          <p className="text-[11px] text-tertiary">
            {messages.auth.usernameHint}
          </p>
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="new-user-password"
            className="block text-xs font-medium text-foreground"
          >
            {messages.users.initialPassword}
          </label>
          <input
            id="new-user-password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={messages.auth.passwordMinHint}
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="new-user-role"
            className="block text-xs font-medium text-foreground"
          >
            {messages.users.colRole}
          </label>
          <select
            id="new-user-role"
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground focus:border-foreground focus:outline-none"
          >
            <option value="user">{messages.users.roleOptionUser}</option>
            <option value="admin">{messages.users.roleOptionAdmin}</option>
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
            {messages.common.cancel}
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting
              ? messages.common.creating
              : messages.users.submitCreate}
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
  const { messages } = useI18n();
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
      setError(messages.users.newPasswordMinError);
      return;
    }
    if (password !== confirm) {
      setError(messages.auth.passwordMismatchError);
      return;
    }

    setSubmitting(true);
    try {
      const updated = await updateUser(target.id, { password });
      onUpdated(updated);
      handleClose();
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.users.resetFailed,
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalDialog
      open={Boolean(target)}
      onClose={handleClose}
      title={
        target
          ? messages.users.resetTitleFor(target.username)
          : messages.users.resetTitle
      }
      description={messages.users.resetDesc}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1.5">
          <label
            htmlFor="reset-user-password"
            className="block text-xs font-medium text-foreground"
          >
            {messages.users.newPassword}
          </label>
          <input
            id="reset-user-password"
            type="password"
            autoFocus
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={messages.auth.passwordMinHint}
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="reset-user-confirm"
            className="block text-xs font-medium text-foreground"
          >
            {messages.users.confirmNewPassword}
          </label>
          <input
            id="reset-user-confirm"
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder={messages.users.confirmNewPasswordPlaceholder}
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
            {messages.common.cancel}
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? messages.common.saving : messages.users.submitReset}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}
