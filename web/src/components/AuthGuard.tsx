"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/AuthContext";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
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

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-foreground" />
          <p className="text-xs text-secondary">正在验证会话状态</p>
        </div>
      </div>
    );
  }

  if (error && !authenticated && !needsSetup) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-6 text-center">
          <h1 className="text-sm font-semibold tracking-tight text-foreground">
            无法连接到网关服务
          </h1>
          <p className="mt-1.5 font-mono text-xs text-secondary">{error}</p>
          <button
            type="button"
            onClick={() => void refreshAuth()}
            className="mt-4 inline-flex h-8 items-center justify-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90"
          >
            重试连接
          </button>
        </div>
      </div>
    );
  }

  if (shouldRedirectToLogin || !authenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-xs text-secondary">正在跳转至登录页面</p>
      </div>
    );
  }

  return <>{children}</>;
}
