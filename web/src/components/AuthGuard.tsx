"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { AUTH_CONNECTION_ERROR, useAuth } from "@/components/AuthContext";
import { Logo } from "@/components/Logo";
import { useI18n } from "@/lib/i18n";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { messages } = useI18n();
  const {
    needsSetup,
    authenticated,
    isLoading,
    error,
    pendingInitialToken,
    refreshAuth,
  } = useAuth();

  const shouldRedirectToLogin =
    !isLoading &&
    !error &&
    (needsSetup || Boolean(pendingInitialToken) || !authenticated);

  useEffect(() => {
    if (shouldRedirectToLogin) {
      router.replace("/login");
    }
  }, [shouldRedirectToLogin, router]);

  if (isLoading || shouldRedirectToLogin || (!authenticated && !error)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-foreground" />
      </div>
    );
  }

  if (error && !authenticated && !needsSetup) {
    const detail =
      error === AUTH_CONNECTION_ERROR
        ? messages.auth.connectionErrorFallback
        : error;

    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-6 text-center">
          <div className="mb-4 flex items-center justify-center gap-2">
            <Logo className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-tight text-foreground">
              {messages.common.brand}
            </span>
          </div>
          <h1 className="text-sm font-semibold tracking-tight text-foreground">
            {messages.auth.connectionErrorTitle}
          </h1>
          <p className="mt-1.5 font-mono text-xs text-secondary">{detail}</p>
          <button
            type="button"
            onClick={() => void refreshAuth()}
            className="mt-4 inline-flex h-8 items-center justify-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90"
          >
            {messages.common.retry}
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
