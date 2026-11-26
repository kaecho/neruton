import React from "react";
import { AuthGuard } from "@/components/AuthGuard";
import { DashboardShell } from "@/components/DashboardShell";
import { NerutonStreamProvider } from "@/components/StreamContext";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <NerutonStreamProvider>
        <DashboardShell>{children}</DashboardShell>
      </NerutonStreamProvider>
    </AuthGuard>
  );
}
