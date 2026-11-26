"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { Moon, Sun } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import { Logo } from "@/components/Logo";
import { useTheme } from "@/hooks/useTheme";
import { loginAccount } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const SetupAccountView = dynamic(
  () =>
    import("@/components/SetupAccountView").then((m) => m.SetupAccountView),
  { ssr: false },
);

export default function LoginPage() {
  const router = useRouter();
  const { messages } = useI18n();
  const { theme, toggleTheme, mounted: themeMounted } = useTheme();
  const {
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

  const utilityBar = (
    <div className="fixed right-4 top-4 z-20 flex items-center gap-2">
      <LocaleSwitcher />
      <button
        type="button"
        onClick={toggleTheme}
        aria-label={messages.common.toggleTheme}
        title={messages.common.toggleTheme}
        className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-background text-secondary transition-colors hover:border-border-strong hover:text-foreground"
      >
        {themeMounted && theme === "dark" ? (
          <Sun className="h-4 w-4" />
        ) : (
          <Moon className="h-4 w-4" />
        )}
      </button>
    </div>
  );

  if (isLoading) {
    return (
      <div className="relative flex min-h-screen items-center justify-center bg-background">
        {utilityBar}
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-foreground" />
      </div>
    );
  }

  if (needsSetup || pendingInitialToken) {
    return (
      <div className="relative min-h-screen bg-background">
        {utilityBar}
        <SetupAccountView />
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim() || !password) {
      setError(messages.auth.missingCredentials);
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
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.auth.invalidCredentials,
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12">
      {utilityBar}

      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <Logo className="h-6 w-6" />
          <h1 className="text-base font-semibold tracking-tight text-foreground">
            {messages.common.brand}
          </h1>
        </div>

        <div className="rounded-lg border border-border bg-background p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="login-username"
                className="block text-xs font-medium text-foreground"
              >
                {messages.auth.username}
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={messages.auth.usernamePlaceholder}
                className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="login-password"
                className="block text-xs font-medium text-foreground"
              >
                {messages.auth.password}
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={messages.auth.passwordPlaceholder}
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
              {submitting ? messages.auth.signingIn : messages.auth.signIn}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
