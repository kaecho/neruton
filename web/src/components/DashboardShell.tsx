"use client";

import React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut, Moon, Sun } from "lucide-react";
import { useAuth } from "@/components/AuthContext";
import { Logo } from "@/components/Logo";
import { useSharedStream } from "@/components/StreamContext";
import { useTheme } from "@/hooks/useTheme";

interface NavItem {
  href: string;
  label: string;
  adminOnly?: boolean;
}

const NAV_ITEMS: readonly NavItem[] = [
  { href: "/", label: "概览" },
  { href: "/tokens", label: "令牌" },
  { href: "/logs", label: "日志" },
  { href: "/users", label: "用户", adminOnly: true },
  { href: "/settings", label: "设置" },
];

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, status, logout } = useAuth();
  const { info } = useSharedStream();
  const { theme, toggleTheme, mounted } = useTheme();

  const isAdmin = user?.role === "admin";
  const baseDomain = info?.base_domain || status?.base_domain || "moer.eu.org";

  const visibleNav = NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin);

  const handleLogout = async () => {
    await logout();
    router.replace("/login");
  };

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      {/* Top Compact Header */}
      <header className="bg-background">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          {/* Left: Mark + Wordmark + Domain Context */}
          <div className="flex min-w-0 items-center gap-2.5">
            <Link
              href="/"
              className="inline-flex shrink-0 items-center gap-2 text-sm font-semibold tracking-tight text-foreground"
            >
              <Logo className="h-5 w-5" />
              <span>Neruton</span>
            </Link>
            <span
              aria-hidden="true"
              className="text-border-strong select-none text-base font-light"
            >
              /
            </span>
            <span className="truncate font-mono text-xs text-secondary">
              *.{baseDomain}
            </span>
          </div>

          {/* Right: User context + Theme Toggle + Sign Out */}
          <div className="flex shrink-0 items-center gap-2">
            {user ? (
              <div className="flex items-center gap-2">
                <span className="hidden text-xs font-medium text-foreground sm:inline">
                  {user.username}
                </span>
                <span className="inline-flex items-center rounded-full border border-border bg-surface px-2 py-0.5 font-mono text-[11px] text-secondary">
                  {user.role === "admin" ? "admin" : "user"}
                </span>
              </div>
            ) : null}

            <div className="mx-0.5 h-4 w-px bg-border" aria-hidden="true" />

            <button
              type="button"
              onClick={toggleTheme}
              aria-label="切换明暗主题"
              title="切换明暗主题"
              className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-transparent text-secondary transition-colors hover:border-border hover:bg-surface hover:text-foreground"
            >
              {mounted && theme === "dark" ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
            </button>

            <button
              type="button"
              onClick={handleLogout}
              title="退出登录"
              aria-label="退出登录"
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-transparent px-2 text-xs text-secondary transition-colors hover:border-border hover:bg-surface hover:text-foreground"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">退出</span>
            </button>
          </div>
        </div>
      </header>

      {/* Sticky Sub-Navigation Bar */}
      <nav
        aria-label="主导航"
        className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur-xs"
      >
        <div className="mx-auto flex h-11 max-w-6xl items-center gap-1 overflow-x-auto px-4 sm:px-6">
          {visibleNav.map((item) => {
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname === item.href ||
                  pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`relative flex h-full shrink-0 items-center px-3 text-xs font-medium transition-colors ${
                  active
                    ? "text-foreground"
                    : "text-secondary hover:text-foreground"
                }`}
              >
                {item.label}
                {active ? (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 bottom-0 h-[2px] bg-foreground"
                  />
                ) : null}
              </Link>
            );
          })}
        </div>
      </nav>

      {/* Page Body */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        {children}
      </main>
    </div>
  );
}
