"use client";

import React, { createContext, useContext } from "react";
import { useAuth } from "@/components/AuthContext";
import {
  useNerutonStream,
  type UseNerutonStreamResult,
} from "@/hooks/useNerutonStream";

const StreamContext = createContext<UseNerutonStreamResult | null>(null);

export function NerutonStreamProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const { authenticated, handleUnauthorized } = useAuth();
  const stream = useNerutonStream({
    enabled: authenticated,
    onUnauthorized: handleUnauthorized,
  });

  return (
    <StreamContext.Provider value={stream}>{children}</StreamContext.Provider>
  );
}

export function useSharedStream(): UseNerutonStreamResult {
  const ctx = useContext(StreamContext);
  if (!ctx) {
    throw new Error("useSharedStream must be used inside NerutonStreamProvider");
  }
  return ctx;
}
