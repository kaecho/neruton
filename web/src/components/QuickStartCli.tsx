"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { ChevronDown, ChevronRight, Terminal } from "lucide-react";
import { CodeBlock } from "@/components/GeistPrimitives";
import { resolveCliServerArg, resolvePanelOrigin } from "@/lib/api";
import { validateSubdomainPrefix } from "@/lib/format";
import type { ServerInfo } from "@/lib/types";

interface QuickStartCliProps {
  info: ServerInfo | null;
  reservedPrefixes?: string[];
  initialSubdomain?: string;
  defaultOpen?: boolean;
  collapsible?: boolean;
}

const PORT_PRESETS = [
  { label: ":3000", url: "http://localhost:3000" },
  { label: ":5173", url: "http://localhost:5173" },
  { label: ":8000", url: "http://localhost:8000" },
  { label: ":8080", url: "http://localhost:8080" },
  { label: ":11434", url: "http://localhost:11434" },
] as const;

export function QuickStartCli({
  info,
  reservedPrefixes,
  initialSubdomain,
  defaultOpen = false,
  collapsible = true,
}: QuickStartCliProps) {
  const [open, setOpen] = useState(defaultOpen || !collapsible);
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");
  const [prefixMode, setPrefixMode] = useState<"uuid" | "custom">(
    initialSubdomain ? "custom" : "uuid",
  );
  const [customPrefix, setCustomPrefix] = useState(
    initialSubdomain || "app-dev",
  );
  const [tokenInput, setTokenInput] = useState("");
  const [activeTab, setActiveTab] = useState<"tunnel" | "config">("tunnel");

  const cliServer = resolveCliServerArg(info);
  const panelOrigin = resolvePanelOrigin(info);
  const scheme = info?.public_scheme || "https";
  const baseDomain =
    info?.base_domain || process.env.NEXT_PUBLIC_BASE_DOMAIN || "moer.eu.org";
  const requireAuth = info ? (info.require_tunnel_auth ?? info.auth_required) : true;

  const validation = useMemo(
    () => validateSubdomainPrefix(customPrefix, reservedPrefixes),
    [customPrefix, reservedPrefixes],
  );

  const effectivePrefix =
    prefixMode === "custom"
      ? validation.normalized || "app-dev"
      : "<auto-uuid>";

  const sanitizedTarget = targetUrl.trim() || "http://localhost:3000";
  const effectiveToken = tokenInput.trim() || "<YOUR_TOKEN>";

  const configCommand = `neruton config set --token ${effectiveToken}`;

  const tunnelCommand = useMemo(() => {
    const parts = [
      "neruton",
      "tunnel",
      "--server",
      cliServer,
      "--url",
      sanitizedTarget,
    ];
    if (prefixMode === "custom") {
      parts.push("--subdomain", validation.normalized || "app-dev");
    }
    if (tokenInput.trim()) {
      parts.push("--token", tokenInput.trim());
    }
    return parts.join(" ");
  }, [cliServer, sanitizedTarget, prefixMode, validation.normalized, tokenInput]);

  const expectedWildcardUrl = `${scheme}://${effectivePrefix}.${baseDomain}`;
  const expectedPreviewUrl = `${panelOrigin}/preview/${effectivePrefix}`;

  return (
    <section
      aria-label="快速连接 CLI"
      className="rounded-lg border border-border bg-background"
    >
      {collapsible ? (
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          aria-expanded={open}
          className="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-surface"
        >
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-secondary" />
            <span className="text-xs font-medium text-foreground">
              快速连接 CLI
            </span>
            <span className="hidden text-xs text-secondary sm:inline">
              生成本地客户端配置与启动命令
            </span>
          </div>
          {open ? (
            <ChevronDown className="h-4 w-4 text-secondary" />
          ) : (
            <ChevronRight className="h-4 w-4 text-secondary" />
          )}
        </button>
      ) : (
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-secondary" />
            <span className="text-xs font-medium text-foreground">
              启动隧道命令
            </span>
          </div>
        </div>
      )}

      {open ? (
        <div
          className={`space-y-4 p-4 ${collapsible ? "border-t border-border" : ""}`}
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {/* Target URL */}
            <div className="space-y-1.5">
              <label
                htmlFor="cli-target-url"
                className="block text-xs font-medium text-foreground"
              >
                本地服务地址
              </label>
              <input
                id="cli-target-url"
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://localhost:3000"
                className="h-8 w-full rounded-md border border-border bg-background px-2.5 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
              <div className="flex flex-wrap gap-1">
                {PORT_PRESETS.map((preset) => {
                  const active = targetUrl.trim() === preset.url;
                  return (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => setTargetUrl(preset.url)}
                      className={`rounded border px-1.5 py-0.5 font-mono text-[11px] transition-colors ${
                        active
                          ? "border-foreground bg-foreground text-background"
                          : "border-border bg-surface text-secondary hover:text-foreground"
                      }`}
                    >
                      {preset.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Prefix Mode */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">
                  子域名前缀
                </span>
                <div className="inline-flex rounded-md border border-border bg-surface p-0.5 text-[11px]">
                  <button
                    type="button"
                    onClick={() => setPrefixMode("uuid")}
                    className={`rounded px-2 py-0.5 transition-colors ${
                      prefixMode === "uuid"
                        ? "bg-background font-medium text-foreground"
                        : "text-secondary hover:text-foreground"
                    }`}
                  >
                    自动 UUID
                  </button>
                  <button
                    type="button"
                    onClick={() => setPrefixMode("custom")}
                    className={`rounded px-2 py-0.5 transition-colors ${
                      prefixMode === "custom"
                        ? "bg-background font-medium text-foreground"
                        : "text-secondary hover:text-foreground"
                    }`}
                  >
                    自定义
                  </button>
                </div>
              </div>

              {prefixMode === "custom" ? (
                <div>
                  <div className="flex h-8 items-center overflow-hidden rounded-md border border-border bg-background focus-within:border-foreground">
                    <input
                      type="text"
                      value={customPrefix}
                      onChange={(e) => setCustomPrefix(e.target.value)}
                      placeholder="app-dev"
                      aria-label="自定义子域名前缀"
                      className="min-w-0 flex-1 bg-transparent px-2.5 font-mono text-xs text-foreground placeholder:text-tertiary focus:outline-none"
                    />
                    <span className="shrink-0 border-l border-border bg-surface px-2 py-1.5 font-mono text-[11px] text-secondary">
                      .{baseDomain}
                    </span>
                  </div>
                  {!validation.valid && validation.error ? (
                    <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                      {validation.error}
                    </p>
                  ) : null}
                </div>
              ) : (
                <p className="text-[11px] leading-relaxed text-secondary">
                  省略 <code className="font-mono text-foreground">--subdomain</code>{" "}
                  时自动分配唯一 UUID 前缀。
                </p>
              )}
            </div>

            {/* Optional Token Input */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="cli-token-input"
                  className="text-xs font-medium text-foreground"
                >
                  隧道令牌
                </label>
                <Link
                  href="/tokens"
                  className="text-[11px] text-secondary underline-offset-4 hover:text-foreground hover:underline"
                >
                  管理令牌
                </Link>
              </div>
              <input
                id="cli-token-input"
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder={
                  requireAuth ? "粘贴 ntk_... 令牌" : "可选（当前为开放模式）"
                }
                className="h-8 w-full rounded-md border border-border bg-background px-2.5 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
              />
              <p className="text-[11px] text-secondary">
                {requireAuth
                  ? "当前已强制开启隧道令牌鉴权，需先配置令牌。"
                  : "当前为开放模式，可省略令牌或按需填入。"}
              </p>
            </div>
          </div>

          {/* Command Tabs */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between border-b border-border">
              <div className="flex items-center gap-4">
                <button
                  type="button"
                  onClick={() => setActiveTab("tunnel")}
                  className={`relative pb-2 text-xs font-medium transition-colors ${
                    activeTab === "tunnel"
                      ? "text-foreground"
                      : "text-secondary hover:text-foreground"
                  }`}
                >
                  启动隧道
                  {activeTab === "tunnel" ? (
                    <span className="absolute inset-x-0 bottom-0 h-[2px] bg-foreground" />
                  ) : null}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("config")}
                  className={`relative pb-2 text-xs font-medium transition-colors ${
                    activeTab === "config"
                      ? "text-foreground"
                      : "text-secondary hover:text-foreground"
                  }`}
                >
                  保存令牌配置
                  {activeTab === "config" ? (
                    <span className="absolute inset-x-0 bottom-0 h-[2px] bg-foreground" />
                  ) : null}
                </button>
              </div>
              <span className="hidden font-mono text-[11px] text-tertiary sm:inline">
                {expectedWildcardUrl}
              </span>
            </div>

            {activeTab === "tunnel" ? (
              <CodeBlock code={tunnelCommand} />
            ) : (
              <CodeBlock code={configCommand} />
            )}

            <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-secondary">
              <span>
                泛域名:{" "}
                <code className="font-mono text-foreground">
                  {expectedWildcardUrl}
                </code>
              </span>
              <span>
                内嵌预览:{" "}
                <code className="font-mono text-foreground">
                  {expectedPreviewUrl}
                </code>
              </span>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
