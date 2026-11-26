"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Check } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { CodeBlock, CopyButton } from "@/components/GeistPrimitives";
import { Logo } from "@/components/Logo";
import { resolveCliServerArg, setupAdminAccount } from "@/lib/api";
import { validateUsername } from "@/lib/format";

export function SetupAccountView() {
  const router = useRouter();
  const {
    status,
    pendingInitialToken,
    completeSetup,
    dismissInitialToken,
  } = useAuth();

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const cliServer = resolveCliServerArg(status);

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
    if (password !== confirmPassword) {
      setError("两次输入的密码不一致");
      return;
    }

    setSubmitting(true);
    try {
      const res = await setupAdminAccount({
        username: username.trim(),
        password,
      });
      completeSetup(res.user, res.initial_token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "初始化管理员账户失败");
    } finally {
      setSubmitting(false);
    }
  };

  const handleEnterDashboard = () => {
    dismissInitialToken();
    router.replace("/");
  };

  if (pendingInitialToken) {
    const secret = pendingInitialToken.secret;
    const configCmd = `neruton config set --token ${secret}`;
    const tunnelCmd = `neruton tunnel --server ${cliServer} --url http://localhost:3000`;

    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12">
        <div className="w-full max-w-lg rounded-lg border border-border bg-background p-6 sm:p-8">
          <div className="flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-full border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <Check className="h-3.5 w-3.5" />
            </div>
            <h1 className="text-base font-semibold tracking-tight text-foreground">
              管理员账户已初始化
            </h1>
          </div>

          <p className="mt-2 text-xs leading-relaxed text-secondary">
            系统已为您生成默认 CLI 隧道令牌（
            <span className="font-mono text-foreground">
              {pendingInitialToken.token.name}
            </span>
            ）。该密钥仅显示一次，关闭后无法再次查看，请妥善保存。
          </p>

          <div className="mt-5 space-y-4">
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">
                  默认隧道令牌（一次性密钥）
                </span>
                <CopyButton text={secret} label="复制密钥" />
              </div>
              <div className="overflow-x-auto rounded-md border border-border bg-surface px-3 py-2.5 font-mono text-xs text-foreground">
                {secret}
              </div>
            </div>

            <div className="space-y-2">
              <span className="block text-xs font-medium text-foreground">
                快速配置本地 CLI
              </span>
              <CodeBlock label="1. 保存默认令牌" code={configCmd} />
              <CodeBlock label="2. 启动穿透隧道" code={tunnelCmd} />
            </div>
          </div>

          <div className="mt-6 flex items-center justify-end border-t border-border pt-5">
            <button
              type="button"
              onClick={handleEnterDashboard}
              className="inline-flex h-9 items-center gap-1.5 rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90"
            >
              <span>进入控制台</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    );
  }

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
            初始化管理员账户
          </h1>
          <p className="mt-1 text-xs text-secondary">
            首次运行需创建管理员账户，用于管理用户、隧道令牌与网关策略。
          </p>

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="setup-username"
                className="block text-xs font-medium text-foreground"
              >
                管理员用户名
              </label>
              <input
                id="setup-username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
              <p className="text-[11px] text-tertiary">
                3-32 位字母、数字或 . _ -
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="setup-password"
                className="block text-xs font-medium text-foreground"
              >
                密码
              </label>
              <input
                id="setup-password"
                type="password"
                autoComplete="new-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="至少 8 位字符"
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="setup-confirm"
                className="block text-xs font-medium text-foreground"
              >
                确认密码
              </label>
              <input
                id="setup-confirm"
                type="password"
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入密码"
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
              {submitting ? "正在创建账户..." : "创建管理员账户"}
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
