"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { fetchAuthStatus, logoutAccount } from "@/lib/api";
import type {
  AuthStatusResponse,
  CreateTokenResponse,
  UserPublic,
} from "@/lib/types";

export const AUTH_CONNECTION_ERROR = "__AUTH_CONNECTION_ERROR__";

interface AuthContextValue {
  status: AuthStatusResponse | null;
  user: UserPublic | null;
  needsSetup: boolean;
  authenticated: boolean;
  isLoading: boolean;
  error: string | null;
  pendingInitialToken: CreateTokenResponse | null;
  refreshAuth: () => Promise<AuthStatusResponse | null>;
  completeLogin: (user: UserPublic) => void;
  completeSetup: (user: UserPublic, initialToken: CreateTokenResponse) => void;
  dismissInitialToken: () => void;
  handleUnauthorized: () => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingInitialToken, setPendingInitialToken] =
    useState<CreateTokenResponse | null>(null);

  const refreshAuth = useCallback(async () => {
    try {
      const next = await fetchAuthStatus();
      setStatus(next);
      setError(null);
      return next;
    } catch (err) {
      const msg =
        err instanceof Error && err.message
          ? err.message
          : AUTH_CONNECTION_ERROR;
      setError(msg);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    fetchAuthStatus(controller.signal)
      .then((next) => {
        if (!active) return;
        setStatus(next);
        setError(null);
      })
      .catch((err) => {
        if (!active || controller.signal.aborted) return;
        setError(
          err instanceof Error && err.message
            ? err.message
            : AUTH_CONNECTION_ERROR,
        );
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  const completeLogin = useCallback((user: UserPublic) => {
    setStatus((prev) => ({
      needs_setup: false,
      authenticated: true,
      user,
      panel_host: prev?.panel_host ?? "",
      base_domain: prev?.base_domain ?? "",
      public_scheme: prev?.public_scheme ?? "https",
      version: prev?.version ?? "",
    }));
    setError(null);
  }, []);

  const completeSetup = useCallback(
    (user: UserPublic, initialToken: CreateTokenResponse) => {
      setPendingInitialToken(initialToken);
      setStatus((prev) => ({
        needs_setup: false,
        authenticated: true,
        user,
        panel_host: prev?.panel_host ?? "",
        base_domain: prev?.base_domain ?? "",
        public_scheme: prev?.public_scheme ?? "https",
        version: prev?.version ?? "",
      }));
      setError(null);
    },
    [],
  );

  const dismissInitialToken = useCallback(() => {
    setPendingInitialToken(null);
  }, []);

  const handleUnauthorized = useCallback(() => {
    setStatus((prev) =>
      prev
        ? { ...prev, authenticated: false, user: null }
        : prev,
    );
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutAccount();
    } catch {
      // Clear local session state even if server returns error
    }
    setPendingInitialToken(null);
    setStatus((prev) =>
      prev
        ? { ...prev, authenticated: false, user: null }
        : prev,
    );
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user: status?.user ?? null,
      needsSetup: Boolean(status?.needs_setup),
      authenticated: Boolean(status?.authenticated && status?.user),
      isLoading,
      error,
      pendingInitialToken,
      refreshAuth,
      completeLogin,
      completeSetup,
      dismissInitialToken,
      handleUnauthorized,
      logout,
    }),
    [
      status,
      isLoading,
      error,
      pendingInitialToken,
      refreshAuth,
      completeLogin,
      completeSetup,
      dismissInitialToken,
      handleUnauthorized,
      logout,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return ctx;
}
