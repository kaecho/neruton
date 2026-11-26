"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/AuthContext";
import { Logo } from "@/components/Logo";
import { SetupAccountView } from "@/components/SetupAccountView";
import { loginAccount } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const {
    status,
    needsSetup,
    authenticated,
    isLoading,
    pendingInitialToken,
    completeLogin,
  } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isLoading && authenticated && !needsSetup && !pendingInitialToken) {
      router.replace("/");
    }
  }, [isLoading, authenticated, needsSetup, pendingInitialToken, router]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-foreground" />
      </div>
    );
  }

  if (needsSetup || pendingInitialToken) {
    return <SetupAccountView />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim() || !password) {
      setError("请输入用户名和密码");
      return;
    }

    setSubmitting(true);
    try {
      const res = await loginAccount({
        username: username.trim(),
        password,
      });
      completeLogin(res.user);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "用户名或密码错误");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <Logo className="h-6 w-6" />
          <span className="text-base font-semibold tracking-tight text-foreground">
            Neruton
          </span>
        </div>

        <div className="rounded-lg border border-border bg-background p-6">
          <h1 className="text-base font-semibold tracking-tight text-foreground">
            登录控制台
          </h1>
          <p className="mt-1 text-xs text-secondary">
            输入账户凭据以管理穿透隧道、令牌与访问日志。
          </p>

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="login-username"
                className="block text-xs font-medium text-foreground"
              >
                用户名
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="输入用户名"
                className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="login-password"
                className="block text-xs font-medium text-foreground"
              >
                密码
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="输入密码"
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

            <button
              type="submit"
              disabled={submitting}
              className="flex h-9 w-full items-center justify-center rounded-md bg-foreground text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "正在登录..." : "登录"}
            </button>
          </form>
        </div>

        {status?.base_domain ? (
          <p className="mt-4 text-center font-mono text-[11px] text-tertiary">
            {status.panel_host || status.base_domain} · v{status.version}
          </p>
        ) : null}
      </div>
    </div>
  );
}
