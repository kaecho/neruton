"use client";

import React, { useMemo, useState } from "react";
import {
  Check,
  Copy,
  Globe,
  Monitor,
  Route,
  Sparkles,
  Terminal,
} from "lucide-react";
import { resolvePanelOrigin } from "@/lib/api";
import { copyToClipboard, validateSubdomainPrefix } from "@/lib/format";
import type { ServerInfo } from "@/lib/types";

interface QuickStartCliProps {
  info: ServerInfo | null;
  adminToken?: string;
  compact?: boolean;
  initialSubdomain?: string;
  title?: string;
  subtitle?: string;
}

const PORT_PRESETS = [
  { label: ":3000", url: "http://localhost:3000", desc: "Next.js / Node" },
  { label: ":5173", url: "http://localhost:5173", desc: "Vite" },
  { label: ":8000", url: "http://localhost:8000", desc: "Python / FastAPI" },
  { label: ":8080", url: "http://localhost:8080", desc: "Go / Web" },
  { label: ":11434", url: "http://localhost:11434", desc: "Ollama / API" },
];

export function QuickStartCli({
  info,
  adminToken = "",
  compact = false,
  initialSubdomain,
  title = "快速启动 CLI 生成器",
  subtitle = "选择本地服务地址与子域名模式，一键复制命令即可建立穿透隧道。",
}: QuickStartCliProps) {
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");
  const [prefixMode, setPrefixMode] = useState<"uuid" | "custom">(
    initialSubdomain ? "custom" : "uuid",
  );
  const [customPrefix, setCustomPrefix] = useState(
    initialSubdomain || "test-test",
  );
  const [commandStyle, setCommandStyle] = useState<"tunnel" | "http">("tunnel");
  const [includeToken, setIncludeToken] = useState(Boolean(info?.auth_required));
  const [copiedCmd, setCopiedCmd] = useState(false);

  const panelOrigin = resolvePanelOrigin(info);
  const scheme = info?.public_scheme || "https";
  const baseDomain =
    info?.base_domain || process.env.NEXT_PUBLIC_BASE_DOMAIN || "moer.eu.org";

  const validation = useMemo(
    () => validateSubdomainPrefix(customPrefix),
    [customPrefix],
  );

  const effectivePrefix =
    prefixMode === "custom"
      ? validation.normalized || "test-test"
      : "<auto-uuid>";

  const sanitizedTarget = targetUrl.trim() || "http://localhost:3000";

  const command = useMemo(() => {
    const parts: string[] = [];
    if (commandStyle === "http") {
      const portMatch = sanitizedTarget.match(
        /^https?:\/\/(?:localhost|127\.0\.0\.1):(\d+)\/?$/i,
      );
      parts.push("neruton", "http", portMatch ? portMatch[1] : sanitizedTarget);
      parts.push("--server", panelOrigin);
    } else {
      parts.push(
        "neruton",
        "tunnel",
        "--server",
        panelOrigin,
        "--url",
        sanitizedTarget,
      );
    }

    if (prefixMode === "custom") {
      parts.push("--subdomain", validation.normalized || "test-test");
    }

    if (includeToken || info?.auth_required) {
      parts.push("--token", adminToken ? adminToken : "<YOUR_TOKEN>");
    }

    return parts.join(" ");
  }, [
    commandStyle,
    sanitizedTarget,
    panelOrigin,
    prefixMode,
    validation.normalized,
    includeToken,
    info?.auth_required,
    adminToken,
  ]);

  const expectedWildcardUrl = `${scheme}://${effectivePrefix}.${baseDomain}`;
  const expectedPreviewUrl = `${panelOrigin}/preview/${effectivePrefix}`;
  const expectedPathUrl = `${panelOrigin}/t/${effectivePrefix}/`;

  const handleCopy = async () => {
    const ok = await copyToClipboard(command);
    if (ok) {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1800);
    }
  };

  return (
    <div
      className={`rounded-2xl border border-zinc-200/90 bg-white/90 shadow-xs backdrop-blur-md dark:border-zinc-800/80 dark:bg-zinc-900/65 ${
        compact ? "p-4" : "p-5 sm:p-6"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 text-cyan-600 dark:text-cyan-400">
            <Terminal className="h-4.5 w-4.5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              {title}
            </h3>
            <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
              {subtitle}
            </p>
          </div>
        </div>

        {/* Command style switch */}
        <div className="inline-flex rounded-lg border border-zinc-200 bg-zinc-100/80 p-0.5 text-[11px] dark:border-zinc-800 dark:bg-zinc-950/80">
          <button
            type="button"
            onClick={() => setCommandStyle("tunnel")}
            className={`rounded-md px-2.5 py-1 font-medium transition ${
              commandStyle === "tunnel"
                ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-800 dark:text-zinc-100"
                : "text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200"
            }`}
          >
            完整命令
          </button>
          <button
            type="button"
            onClick={() => setCommandStyle("http")}
            className={`rounded-md px-2.5 py-1 font-medium transition ${
              commandStyle === "http"
                ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-800 dark:text-zinc-100"
                : "text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200"
            }`}
          >
            快捷写法
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Local Target URL */}
        <div className="space-y-2">
          <label
            htmlFor="quickstart-target-url"
            className="block text-xs font-medium text-zinc-700 dark:text-zinc-300"
          >
            本地服务地址 (--url)
          </label>
          <input
            id="quickstart-target-url"
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:3000"
            className="w-full rounded-xl border border-zinc-300 bg-zinc-50 px-3.5 py-2 font-mono text-xs text-zinc-900 placeholder:text-zinc-400 focus:border-cyan-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/20 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-100 dark:placeholder:text-zinc-500"
          />
          <div className="flex flex-wrap gap-1.5">
            {PORT_PRESETS.map((preset) => {
              const active = targetUrl.trim() === preset.url;
              return (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => setTargetUrl(preset.url)}
                  className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-[11px] transition ${
                    active
                      ? "border-cyan-500/50 bg-cyan-500/12 font-medium text-cyan-700 dark:text-cyan-300"
                      : "border-zinc-200 bg-zinc-50 text-zinc-600 hover:border-zinc-300 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/70 dark:text-zinc-400 dark:hover:border-zinc-700 dark:hover:text-zinc-200"
                  }`}
                >
                  <span className="font-mono">{preset.label}</span>
                  <span className="hidden text-[10px] opacity-70 sm:inline">
                    {preset.desc}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Subdomain prefix mode */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">
              子域名前缀模式 (--subdomain)
            </span>
            {!info?.auth_required && (
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-zinc-500 dark:text-zinc-400">
                <input
                  type="checkbox"
                  checked={includeToken}
                  onChange={(e) => setIncludeToken(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-zinc-300 accent-cyan-500 dark:border-zinc-700"
                />
                附带 --token
              </label>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setPrefixMode("uuid")}
              className={`flex items-center justify-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition ${
                prefixMode === "uuid"
                  ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"
                  : "border-zinc-200 bg-zinc-50 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400 dark:hover:bg-zinc-900"
              }`}
            >
              <Sparkles className="h-3.5 w-3.5" />
              自动 UUID
            </button>
            <button
              type="button"
              onClick={() => setPrefixMode("custom")}
              className={`flex items-center justify-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition ${
                prefixMode === "custom"
                  ? "border-emerald-500/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : "border-zinc-200 bg-zinc-50 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400 dark:hover:bg-zinc-900"
              }`}
            >
              <Globe className="h-3.5 w-3.5" />
              自定义前缀
            </button>
          </div>

          {prefixMode === "custom" ? (
            <div className="space-y-1">
              <div className="flex items-center overflow-hidden rounded-xl border border-zinc-300 bg-zinc-50 focus-within:border-emerald-500 focus-within:ring-2 focus-within:ring-emerald-500/20 dark:border-zinc-800 dark:bg-zinc-950">
                <input
                  type="text"
                  value={customPrefix}
                  onChange={(e) => setCustomPrefix(e.target.value)}
                  placeholder="test-test"
                  className="w-full bg-transparent px-3 py-1.5 font-mono text-xs text-zinc-900 placeholder:text-zinc-400 focus:outline-none dark:text-zinc-100"
                />
                <span className="shrink-0 border-l border-zinc-200 bg-zinc-100 px-2.5 py-1.5 font-mono text-[11px] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400">
                  .{baseDomain}
                </span>
              </div>
              {!validation.valid && validation.error && (
                <p className="text-[11px] text-amber-600 dark:text-amber-400">
                  {validation.error}
                </p>
              )}
            </div>
          ) : (
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
              省略{" "}
              <code className="rounded bg-zinc-100 px-1 py-0.5 font-mono text-[10px] dark:bg-zinc-800">
                --subdomain
              </code>{" "}
              时将自动分配唯一随机 UUID 前缀，断线重连后保持不变。
            </p>
          )}
        </div>
      </div>

      {/* Generated CLI Command Box */}
      <div className="mt-4 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 text-zinc-100 shadow-inner">
        <div className="flex items-center justify-between border-b border-zinc-800/90 bg-zinc-900/80 px-3.5 py-2">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/75" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/75" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/75" />
            <span className="ml-2 font-mono text-[11px] text-zinc-400">
              terminal · neruton cli
            </span>
          </div>
          <button
            type="button"
            onClick={handleCopy}
            className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-medium transition ${
              copiedCmd
                ? "bg-emerald-500/20 text-emerald-300"
                : "bg-zinc-800 text-zinc-200 hover:bg-zinc-700"
            }`}
          >
            {copiedCmd ? (
              <>
                <Check className="h-3.5 w-3.5" />
                已复制命令
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                复制命令
              </>
            )}
          </button>
        </div>
        <div className="overflow-x-auto px-4 py-3.5">
          <code className="block whitespace-pre font-mono text-xs leading-relaxed text-cyan-300">
            <span className="select-none text-emerald-400">$ </span>
            {command}
          </code>
        </div>
      </div>

      {/* Expected Access Endpoints Preview */}
      <div className="mt-3.5 grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/80 px-3 py-2 dark:border-zinc-800/80 dark:bg-zinc-950/60">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            <Globe className="h-3 w-3 text-cyan-500" />
            泛域名公网地址
          </div>
          <p className="mt-1 truncate font-mono text-[11px] text-zinc-800 dark:text-zinc-200" title={expectedWildcardUrl}>
            {expectedWildcardUrl}
          </p>
        </div>

        <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/80 px-3 py-2 dark:border-zinc-800/80 dark:bg-zinc-950/60">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            <Monitor className="h-3 w-3 text-emerald-500" />
            Web 内嵌预览地址
          </div>
          <p className="mt-1 truncate font-mono text-[11px] text-zinc-800 dark:text-zinc-200" title={expectedPreviewUrl}>
            {expectedPreviewUrl}
          </p>
        </div>

        <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/80 px-3 py-2 dark:border-zinc-800/80 dark:bg-zinc-950/60">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            <Route className="h-3 w-3 text-sky-500" />
            免域名路径代理
          </div>
          <p className="mt-1 truncate font-mono text-[11px] text-zinc-800 dark:text-zinc-200" title={expectedPathUrl}>
            {expectedPathUrl}
          </p>
        </div>
      </div>
    </div>
  );
}
