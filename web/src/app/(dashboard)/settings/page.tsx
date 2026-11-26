"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Plus, X } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { StatusDot, Switch } from "@/components/GeistPrimitives";
import { useSharedStream } from "@/components/StreamContext";
import {
  ApiError,
  changeOwnPassword,
  fetchSettings,
  updateSettings,
} from "@/lib/api";
import { formatShortDate, validateSubdomainPrefix } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import type { SettingsResponse } from "@/lib/types";

export default function SettingsPage() {
  const router = useRouter();
  const { locale, messages } = useI18n();
  const { user, handleUnauthorized, logout } = useAuth();
  const { patchRequireAuthLocal } = useSharedStream();

  const isAdmin = user?.role === "admin";

  /* ── Admin Settings State ─────────────────────────────────────── */
  const [settings, setSettings] = useState<SettingsResponse | null>(null);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [togglingAuth, setTogglingAuth] = useState(false);

  const [maxTunnelsInput, setMaxTunnelsInput] = useState("0");
  const [customReserved, setCustomReserved] = useState<string[]>([]);
  const [newPrefixInput, setNewPrefixInput] = useState("");
  const [prefixInputError, setPrefixInputError] = useState<string | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policySavedNotice, setPolicySavedNotice] = useState(false);

  /* ── Own Password State ───────────────────────────────────────── */
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);

  const syncFromSettings = useCallback((data: SettingsResponse) => {
    setSettings(data);
    setMaxTunnelsInput(String(data.max_tunnels_per_user ?? 0));
    setCustomReserved(data.reserved_prefixes ?? []);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchSettings(controller.signal)
      .then((data) => {
        syncFromSettings(data);
        setSettingsError(null);
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        if (err instanceof ApiError && err.unauthorized) {
          handleUnauthorized();
          return;
        }
        setSettingsError(
          err instanceof Error && err.message
            ? err.message
            : messages.settings.loadFailed,
        );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingSettings(false);
      });

    return () => controller.abort();
  }, [syncFromSettings, handleUnauthorized, messages.settings.loadFailed]);

  const handleToggleRequireAuth = async (next: boolean) => {
    if (!isAdmin) return;
    setTogglingAuth(true);
    setSettingsError(null);
    try {
      const updated = await updateSettings({ require_tunnel_auth: next });
      syncFromSettings(updated);
      patchRequireAuthLocal(updated.require_tunnel_auth);
    } catch (err) {
      setSettingsError(
        err instanceof Error && err.message
          ? err.message
          : messages.settings.updateAuthFailed,
      );
    } finally {
      setTogglingAuth(false);
    }
  };

  const handleAddReservedPrefix = () => {
    setPrefixInputError(null);
    const trimmed = newPrefixInput.trim().toLowerCase();
    if (!trimmed) return;

    const validation = validateSubdomainPrefix(trimmed, undefined, locale);
    if (!validation.valid) {
      if (settings?.default_reserved_prefixes.includes(trimmed)) {
        setPrefixInputError(messages.settings.prefixAlreadyBuiltin(trimmed));
        return;
      }
      setPrefixInputError(validation.error || messages.settings.prefixInvalid);
      return;
    }

    if (settings?.default_reserved_prefixes.includes(validation.normalized)) {
      setPrefixInputError(
        messages.settings.prefixAlreadyBuiltin(validation.normalized),
      );
      return;
    }

    if (customReserved.includes(validation.normalized)) {
      setPrefixInputError(
        messages.settings.prefixAlreadyAdded(validation.normalized),
      );
      return;
    }

    setCustomReserved((prev) => [...prev, validation.normalized]);
    setNewPrefixInput("");
    setPolicySavedNotice(false);
  };

  const handleRemoveReservedPrefix = (prefix: string) => {
    setCustomReserved((prev) => prev.filter((item) => item !== prefix));
    setPolicySavedNotice(false);
  };

  const handleSaveQuotaAndPrefixes = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdmin) return;
    setSettingsError(null);
    setPolicySavedNotice(false);

    const parsedMax = Number.parseInt(maxTunnelsInput.trim(), 10);
    if (Number.isNaN(parsedMax) || parsedMax < 0) {
      setSettingsError(messages.settings.maxTunnelsError);
      return;
    }

    setSavingPolicy(true);
    try {
      const updated = await updateSettings({
        max_tunnels_per_user: parsedMax,
        reserved_prefixes: customReserved,
      });
      syncFromSettings(updated);
      setPolicySavedNotice(true);
    } catch (err) {
      setSettingsError(
        err instanceof Error && err.message
          ? err.message
          : messages.settings.savePolicyFailed,
      );
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(false);

    if (!currentPassword) {
      setPasswordError(messages.settings.currentPasswordRequired);
      return;
    }
    if (newPassword.length < 8) {
      setPasswordError(messages.users.newPasswordMinError);
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError(messages.settings.newPasswordMismatch);
      return;
    }

    setSavingPassword(true);
    try {
      await changeOwnPassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordSuccess(true);
    } catch (err) {
      setPasswordError(
        err instanceof Error && err.message
          ? err.message
          : messages.settings.changePasswordFailed,
      );
    } finally {
      setSavingPassword(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    router.replace("/login");
  };

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          {messages.settings.title}
        </h1>
        <p className="mt-1 text-xs text-secondary">
          {isAdmin
            ? messages.settings.subtitleAdmin
            : messages.settings.subtitleUser}
        </p>
      </div>

      {settingsError ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2.5 text-xs text-red-600 dark:text-red-400"
        >
          {settingsError}
        </div>
      ) : null}

      {/* Admin Section 1: Tunnel Auth Strategy */}
      {isAdmin ? (
        <section
          aria-label={messages.settings.authSectionAria}
          className="overflow-hidden rounded-lg border border-border bg-background"
        >
          <div className="flex flex-col justify-between gap-4 p-6 sm:flex-row sm:items-start">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold tracking-tight text-foreground">
                  {messages.settings.requireAuthTitle}
                </h2>
                {settings ? (
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2 py-0.5 text-[11px] text-foreground">
                    <StatusDot
                      tone={settings.require_tunnel_auth ? "online" : "warn"}
                    />
                    <span>
                      {settings.require_tunnel_auth
                        ? messages.overview.authEnforced
                        : messages.overview.authOpen}
                    </span>
                  </span>
                ) : null}
              </div>
              <p className="max-w-xl text-xs leading-relaxed text-secondary">
                {settings?.require_tunnel_auth ?? true
                  ? messages.settings.requireAuthOnDesc
                  : messages.settings.requireAuthOffDesc}
              </p>
            </div>

            <div className="flex shrink-0 items-center gap-2.5 pt-0.5">
              <Switch
                checked={settings?.require_tunnel_auth ?? true}
                disabled={loadingSettings || togglingAuth || !settings}
                label={messages.settings.requireAuthToggleAria}
                onChange={(next) => void handleToggleRequireAuth(next)}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border bg-surface px-6 py-3 text-xs text-secondary">
            <span>
              {messages.settings.envTokenLabelBefore}
              <code className="font-mono text-foreground">
                NERUTON_AUTH_TOKEN
              </code>
              {messages.settings.envTokenLabelAfter}
            </span>
            <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-foreground">
              <StatusDot
                tone={settings?.env_token_configured ? "online" : "muted"}
              />
              {settings?.env_token_configured
                ? messages.settings.configured
                : messages.settings.notConfigured}
            </span>
          </div>
        </section>
      ) : null}

      {/* Admin Section 2: Quotas & Reserved Prefixes */}
      {isAdmin ? (
        <form
          onSubmit={handleSaveQuotaAndPrefixes}
          className="overflow-hidden rounded-lg border border-border bg-background"
        >
          <div className="space-y-6 p-6">
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-foreground">
                {messages.settings.quotaTitle}
              </h2>
              <p className="mt-1 text-xs text-secondary">
                {messages.settings.quotaDesc}
              </p>
            </div>

            {/* Max Tunnels Per User */}
            <div className="grid grid-cols-1 gap-3 border-t border-border pt-5 sm:grid-cols-3 sm:items-start">
              <div>
                <label
                  htmlFor="max-tunnels-input"
                  className="text-xs font-medium text-foreground"
                >
                  {messages.settings.maxTunnelsLabel}
                </label>
                <p className="mt-1 text-[11px] text-secondary">
                  {messages.settings.maxTunnelsHintBefore}
                  <code className="font-mono text-foreground">0</code>
                  {messages.settings.maxTunnelsHintAfter}
                </p>
              </div>
              <div className="sm:col-span-2">
                <input
                  id="max-tunnels-input"
                  type="number"
                  min={0}
                  step={1}
                  disabled={loadingSettings}
                  value={maxTunnelsInput}
                  onChange={(e) => {
                    setMaxTunnelsInput(e.target.value);
                    setPolicySavedNotice(false);
                  }}
                  className="h-9 w-36 rounded-md border border-border bg-background px-3 font-mono text-xs tabular-nums text-foreground focus:border-foreground focus:outline-none"
                />
              </div>
            </div>

            {/* Built-in Reserved Prefixes */}
            <div className="grid grid-cols-1 gap-3 border-t border-border pt-5 sm:grid-cols-3 sm:items-start">
              <div>
                <span className="text-xs font-medium text-foreground">
                  {messages.settings.builtinReservedLabel}
                </span>
                <p className="mt-1 text-[11px] text-secondary">
                  {messages.settings.builtinReservedDesc}
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5 sm:col-span-2">
                {(settings?.default_reserved_prefixes ?? []).map((prefix) => (
                  <span
                    key={prefix}
                    className="inline-flex items-center rounded border border-border bg-surface px-2 py-1 font-mono text-[11px] text-secondary"
                  >
                    {prefix}
                  </span>
                ))}
              </div>
            </div>

            {/* Custom Reserved Prefixes */}
            <div className="grid grid-cols-1 gap-3 border-t border-border pt-5 sm:grid-cols-3 sm:items-start">
              <div>
                <label
                  htmlFor="custom-reserved-input"
                  className="text-xs font-medium text-foreground"
                >
                  {messages.settings.customReservedLabel}
                </label>
                <p className="mt-1 text-[11px] text-secondary">
                  {messages.settings.customReservedDesc}
                </p>
              </div>

              <div className="space-y-3 sm:col-span-2">
                <div className="flex gap-2">
                  <input
                    id="custom-reserved-input"
                    type="text"
                    value={newPrefixInput}
                    onChange={(e) => {
                      setNewPrefixInput(e.target.value);
                      setPrefixInputError(null);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        handleAddReservedPrefix();
                      }
                    }}
                    placeholder={messages.settings.customReservedPlaceholder}
                    className="h-9 flex-1 rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={handleAddReservedPrefix}
                    className="inline-flex h-9 shrink-0 items-center gap-1 rounded-md border border-border bg-background px-3 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>{messages.settings.addPrefix}</span>
                  </button>
                </div>

                {prefixInputError ? (
                  <p className="text-[11px] text-amber-600 dark:text-amber-400">
                    {prefixInputError}
                  </p>
                ) : null}

                {customReserved.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {customReserved.map((prefix) => (
                      <span
                        key={prefix}
                        className="inline-flex items-center gap-1 rounded border border-border bg-background py-0.5 pl-2 pr-1 font-mono text-[11px] text-foreground"
                      >
                        <span>{prefix}</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveReservedPrefix(prefix)}
                          aria-label={messages.settings.removePrefixAria(prefix)}
                          className="rounded p-0.5 text-tertiary transition-colors hover:bg-muted hover:text-foreground"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-[11px] text-tertiary">
                    {messages.settings.noCustomReserved}
                  </p>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between border-t border-border bg-surface px-6 py-3">
            <span className="text-xs text-secondary">
              {policySavedNotice
                ? messages.settings.policySaved
                : messages.settings.policyUnsavedHint}
            </span>
            <button
              type="submit"
              disabled={savingPolicy || loadingSettings}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {savingPolicy
                ? messages.common.saving
                : messages.settings.saveChanges}
            </button>
          </div>
        </form>
      ) : null}

      {/* All Users Section 3: Account Security & Password */}
      <form
        onSubmit={handleChangePassword}
        className="overflow-hidden rounded-lg border border-border bg-background"
      >
        <div className="space-y-5 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-foreground">
                {messages.settings.accountSecurityTitle}
              </h2>
              <p className="mt-1 text-xs text-secondary">
                {messages.settings.accountSecurityDesc}
              </p>
            </div>
            {user ? (
              <div className="text-right text-[11px] text-secondary">
                <div className="font-mono text-foreground">
                  {user.username} ({user.role})
                </div>
                <div className="tabular-nums text-tertiary">
                  {messages.settings.createdAt(formatShortDate(user.created_at))}
                </div>
              </div>
            ) : null}
          </div>

          <div className="grid grid-cols-1 gap-4 border-t border-border pt-5 sm:grid-cols-3">
            <div className="space-y-1.5">
              <label
                htmlFor="current-password"
                className="block text-xs font-medium text-foreground"
              >
                {messages.settings.currentPassword}
              </label>
              <input
                id="current-password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder={messages.settings.currentPasswordPlaceholder}
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="new-password"
                className="block text-xs font-medium text-foreground"
              >
                {messages.settings.newPassword}
              </label>
              <input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder={messages.auth.passwordMinHint}
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="confirm-password"
                className="block text-xs font-medium text-foreground"
              >
                {messages.settings.confirmNewPassword}
              </label>
              <input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder={messages.settings.confirmNewPasswordPlaceholder}
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>
          </div>

          {passwordError ? (
            <div
              role="alert"
              className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400"
            >
              {passwordError}
            </div>
          ) : null}

          {passwordSuccess ? (
            <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400">
              {messages.settings.passwordUpdated}
            </div>
          ) : null}
        </div>

        <div className="flex items-center justify-between border-t border-border bg-surface px-6 py-3">
          <span className="text-xs text-secondary">
            {messages.settings.passwordRecommendation}
          </span>
          <button
            type="submit"
            disabled={savingPassword}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {savingPassword
              ? messages.settings.updatingPassword
              : messages.settings.updatePasswordButton}
          </button>
        </div>
      </form>

      {/* Sign Out Card */}
      <section
        aria-label={messages.settings.signOutSectionAria}
        className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border bg-background px-6 py-4"
      >
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-foreground">
            {messages.settings.signOutTitle}
          </h2>
          <p className="mt-0.5 text-xs text-secondary">
            {messages.settings.signOutDesc}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleLogout()}
          className="inline-flex h-8 items-center rounded-md border border-border bg-background px-3.5 text-xs font-medium text-foreground transition-colors hover:border-red-500/40 hover:text-red-600 dark:hover:text-red-400"
        >
          {messages.nav.signOutFull}
        </button>
      </section>
    </div>
  );
}
