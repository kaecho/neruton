"use client";

import React from "react";
import Link from "next/link";
import {
  Globe,
  KeyRound,
  Moon,
  RefreshCw,
  ShieldCheck,
  Sun,
} from "lucide-react";
import { Logo } from "@/components/Logo";
import { useTheme } from "@/hooks/useTheme";
import type { ServerInfo, SseConnectionState } from "@/lib/types";

const GITHUB_REPO_URL = "https://github.com/kaecho/neruton";

interface HeaderProps {
  info: ServerInfo | null;
  sseState: SseConnectionState;
  hasToken: boolean;
  isRefreshing: boolean;
  onRefresh: () => void;
  onOpenTokenModal: () => void;
}

function GitHubIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z"
      />
    </svg>
  );
}

export function Header({
  info,
  sseState,
  hasToken,
  isRefreshing,
  onRefresh,
  onOpenTokenModal,
}: HeaderProps) {
  const { theme, toggleTheme, mounted } = useTheme();

  const statusMeta: Record<
    SseConnectionState,
    { label: string; dot: string; pill: string }
  > = {
    connected: {
      label: "SSE 实时连接",
      dot: "bg-emerald-500 animate-pulse",
      pill: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
    },
    polling: {
      label: "轮询模式 (3s)",
      dot: "bg-amber-500",
      pill: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
    },
    connecting: {
      label: "连接中...",
      dot: "bg-cyan-500 animate-pulse",
      pill: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300",
    },
    error: {
      label: "网关离线",
      dot: "bg-rose-500",
      pill: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
    },
  };

  const currentStatus = statusMeta[sseState];

  return (
    <header className="sticky top-0 z-30 border-b border-zinc-200/80 bg-white/80 backdrop-blur-xl dark:border-zinc-800/80 dark:bg-zinc-950/80">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <Link href="/" className="group flex items-center gap-2.5">
            <Logo className="h-8.5 w-8.5 shrink-0 transition-transform duration-200 group-hover:scale-105" />
            <div className="leading-tight">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
                  Neruton
                </span>
                <span className="hidden rounded-md border border-cyan-500/25 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-cyan-700 dark:text-cyan-300 sm:inline-block">
                  TUNNEL GATEWAY
                </span>
              </div>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                内网穿透控制台 & Web 实时预览
              </p>
            </div>
          </Link>
        </div>

        {/* Status, Domain & Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Domain Info Pill */}
          {info && (
            <div
              className="hidden items-center gap-1.5 rounded-xl border border-zinc-200/90 bg-zinc-100/80 px-2.5 py-1.5 font-mono text-[11px] text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-300 lg:inline-flex"
              title={`面板主机: ${info.panel_host} | 泛域名: *.${info.base_domain}`}
            >
              <Globe className="h-3.5 w-3.5 text-cyan-500" />
              <span className="text-zinc-400 dark:text-zinc-500">*.</span>
              <span className="font-medium text-zinc-800 dark:text-zinc-100">
                {info.base_domain}
              </span>
              <span className="mx-1 text-zinc-300 dark:text-zinc-700">|</span>
              <span className="text-zinc-500 dark:text-zinc-400">
                {info.panel_host}
              </span>
            </div>
          )}

          {/* Live SSE Connection Badge */}
          <div
            className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium ${currentStatus.pill}`}
          >
            <span className={`h-2 w-2 rounded-full ${currentStatus.dot}`} />
            <span>{currentStatus.label}</span>
          </div>

          {/* Admin Token Trigger */}
          {(info?.auth_required || hasToken) && (
            <button
              type="button"
              onClick={onOpenTokenModal}
              className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition ${
                hasToken
                  ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-300"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-700 hover:bg-amber-500/20 dark:text-amber-300"
              }`}
              title="配置管理员 Bearer Token"
            >
              {hasToken ? (
                <>
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">已配置令牌</span>
                </>
              ) : (
                <>
                  <KeyRound className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">管理员令牌</span>
                </>
              )}
            </button>
          )}

          {/* Refresh */}
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
            title="立即刷新状态"
            aria-label="立即刷新状态"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`}
            />
          </button>

          {/* Theme Toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
            title={mounted && theme === "dark" ? "切换到浅色模式" : "切换到深色模式"}
            aria-label="切换明暗主题"
          >
            {mounted && theme === "light" ? (
              <Moon className="h-3.5 w-3.5" />
            ) : (
              <Sun className="h-3.5 w-3.5" />
            )}
          </button>

          {/* GitHub Link */}
          <a
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
            title="GitHub 仓库 (kaecho/neruton)"
            aria-label="GitHub 仓库"
          >
            <GitHubIcon className="h-4 w-4" />
          </a>
        </div>
      </div>
    </header>
  );
}
