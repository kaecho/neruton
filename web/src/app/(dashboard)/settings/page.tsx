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
import type { SettingsResponse } from "@/lib/types";

export default function SettingsPage() {
  const router = useRouter();
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
          err instanceof Error ? err.message : "无法读取系统设置",
        );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingSettings(false);
      });

    return () => controller.abort();
  }, [syncFromSettings, handleUnauthorized]);

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
        err instanceof Error ? err.message : "更新隧道鉴权策略失败",
      );
    } finally {
      setTogglingAuth(false);
    }
  };

  const handleAddReservedPrefix = () => {
    setPrefixInputError(null);
    const trimmed = newPrefixInput.trim().toLowerCase();
    if (!trimmed) return;

    const validation = validateSubdomainPrefix(trimmed);
    if (!validation.valid) {
      // Allow adding even if already in default list? Check explicitly:
      if (settings?.default_reserved_prefixes.includes(trimmed)) {
        setPrefixInputError(`"${trimmed}" 已属于系统内置保留前缀`);
        return;
      }
      setPrefixInputError(validation.error || "无效的子域名前缀");
      return;
    }

    if (settings?.default_reserved_prefixes.includes(validation.normalized)) {
      setPrefixInputError(`"${validation.normalized}" 已属于系统内置保留前缀`);
      return;
    }

    if (customReserved.includes(validation.normalized)) {
      setPrefixInputError(`"${validation.normalized}" 已存在于列表中`);
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
      setSettingsError("每用户最大隧道数必须为大于等于 0 的整数");
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
      setSettingsError(err instanceof Error ? err.message : "保存策略失败");
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(false);

    if (!currentPassword) {
      setPasswordError("请输入当前密码");
      return;
    }
    if (newPassword.length < 8) {
      setPasswordError("新密码长度至少为 8 位");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError("两次输入的新密码不一致");
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
      setPasswordError(err instanceof Error ? err.message : "修改密码失败");
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
          设置
        </h1>
        <p className="mt-1 text-xs text-secondary">
          {isAdmin
            ? "配置隧道鉴权策略、配额与保留前缀，并管理当前账户安全。"
            : "管理当前账户密码与登录会话。"}
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
          aria-label="隧道鉴权策略"
          className="overflow-hidden rounded-lg border border-border bg-background"
        >
          <div className="flex flex-col justify-between gap-4 p-6 sm:flex-row sm:items-start">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold tracking-tight text-foreground">
                  强制要求隧道 Token 鉴权
                </h2>
                {settings ? (
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2 py-0.5 text-[11px] text-foreground">
                    <StatusDot
                      tone={settings.require_tunnel_auth ? "online" : "warn"}
                    />
                    <span>
                      {settings.require_tunnel_auth ? "已启用" : "开放模式"}
                    </span>
                  </span>
                ) : null}
              </div>
              <p className="max-w-xl text-xs leading-relaxed text-secondary">
                {settings?.require_tunnel_auth ?? true
                  ? "当前模式：所有 neruton CLI 连接必须携带有效令牌（ntk_...）或环境变量主令牌；匿名连接将被网关直接拒绝（HTTP 401）。"
                  : "当前模式：开放模式允许未携带令牌的匿名 CLI 连接建立隧道；若客户端提供了令牌，网关仍会校验其有效性与前缀限制。"}
              </p>
            </div>

            <div className="flex shrink-0 items-center gap-2.5 pt-0.5">
              <Switch
                checked={settings?.require_tunnel_auth ?? true}
                disabled={loadingSettings || togglingAuth || !settings}
                label="切换强制要求隧道 Token 鉴权"
                onChange={(next) => void handleToggleRequireAuth(next)}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border bg-surface px-6 py-3 text-xs text-secondary">
            <span>
              环境变量主令牌（<code className="font-mono text-foreground">NERUTON_AUTH_TOKEN</code>）状态：
            </span>
            <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-foreground">
              <StatusDot
                tone={settings?.env_token_configured ? "online" : "muted"}
              />
              {settings?.env_token_configured ? "已配置" : "未配置"}
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
                隧道配额与保留前缀
              </h2>
              <p className="mt-1 text-xs text-secondary">
                控制单个用户的并发隧道上限，以及禁止通过 CLI 注册的系统保留子域名。
              </p>
            </div>

            {/* Max Tunnels Per User */}
            <div className="grid grid-cols-1 gap-3 border-t border-border pt-5 sm:grid-cols-3 sm:items-start">
              <div>
                <label
                  htmlFor="max-tunnels-input"
                  className="text-xs font-medium text-foreground"
                >
                  单用户最大活跃隧道数
                </label>
                <p className="mt-1 text-[11px] text-secondary">
                  设为 <code className="font-mono text-foreground">0</code> 表示不限制。
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
                  系统内置保留前缀
                </span>
                <p className="mt-1 text-[11px] text-secondary">
                  内置核心路由与控制面板主机名，不可移除。
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
                  自定义保留前缀
                </label>
                <p className="mt-1 text-[11px] text-secondary">
                  防止敏感子域名被隧道客户端抢占。
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
                    placeholder="输入子域名前缀，如 billing"
                    className="h-9 flex-1 rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={handleAddReservedPrefix}
                    className="inline-flex h-9 shrink-0 items-center gap-1 rounded-md border border-border bg-background px-3 text-xs font-medium text-foreground transition-colors hover:border-border-strong"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>添加</span>
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
                          aria-label={`移除保留前缀 ${prefix}`}
                          className="rounded p-0.5 text-tertiary transition-colors hover:bg-muted hover:text-foreground"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-[11px] text-tertiary">
                    尚未添加自定义保留前缀。
                  </p>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between border-t border-border bg-surface px-6 py-3">
            <span className="text-xs text-secondary">
              {policySavedNotice
                ? "更改已保存并立即生效。"
                : "更改保存后即时应用于新的隧道连接。"}
            </span>
            <button
              type="submit"
              disabled={savingPolicy || loadingSettings}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {savingPolicy ? "保存中..." : "保存更改"}
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
                账户安全
              </h2>
              <p className="mt-1 text-xs text-secondary">
                修改当前登录账户的密码；修改后将刷新会话凭据，其他设备的旧会话会自动失效。
              </p>
            </div>
            {user ? (
              <div className="text-right text-[11px] text-secondary">
                <div className="font-mono text-foreground">
                  {user.username} ({user.role})
                </div>
                <div className="tabular-nums text-tertiary">
                  创建于 {formatShortDate(user.created_at)}
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
                当前密码
              </label>
              <input
                id="current-password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="输入当前密码"
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="new-password"
                className="block text-xs font-medium text-foreground"
              >
                新密码
              </label>
              <input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="至少 8 位字符"
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="confirm-password"
                className="block text-xs font-medium text-foreground"
              >
                确认新密码
              </label>
              <input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入新密码"
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
              密码已更新，当前会话已同步刷新。
            </div>
          ) : null}
        </div>

        <div className="flex items-center justify-between border-t border-border bg-surface px-6 py-3">
          <span className="text-xs text-secondary">
            建议使用 12 位以上包含大小写字母与数字的组合密码。
          </span>
          <button
            type="submit"
            disabled={savingPassword}
            className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {savingPassword ? "更新中..." : "修改密码"}
          </button>
        </div>
      </form>

      {/* Sign Out Card */}
      <section
        aria-label="退出登录"
        className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border bg-background px-6 py-4"
      >
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-foreground">
            退出当前会话
          </h2>
          <p className="mt-0.5 text-xs text-secondary">
            清除浏览器中的认证 Cookie 并返回登录界面。
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleLogout()}
          className="inline-flex h-8 items-center rounded-md border border-border bg-background px-3.5 text-xs font-medium text-foreground transition-colors hover:border-red-500/40 hover:text-red-600 dark:hover:text-red-400"
        >
          退出登录
        </button>
      </section>
    </div>
  );
}
