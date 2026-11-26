"use client";

import React, { useEffect, useState } from "react";
import { Eye, EyeOff, KeyRound, ShieldCheck, Trash2, X } from "lucide-react";

interface AdminTokenModalProps {
  open: boolean;
  token: string;
  authRequired: boolean;
  reason?: string | null;
  onSave: (token: string) => void;
  onClose: () => void;
}

export function AdminTokenModal({
  open,
  token,
  authRequired,
  reason,
  onSave,
  onClose,
}: AdminTokenModalProps) {
  const [draft, setDraft] = useState(token);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (open) {
      setDraft(token);
      setVisible(false);
    }
  }, [open, token]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(draft.trim());
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="admin-token-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-zinc-950">
        <div className="flex items-center justify-between border-b border-zinc-200 px-5 py-4 dark:border-zinc-800/80">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
              <KeyRound className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2
                id="admin-token-title"
                className="text-sm font-semibold text-zinc-900 dark:text-zinc-100"
              >
                管理员访问令牌 (Admin Token)
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                {authRequired
                  ? "网关已开启 Bearer 认证模式"
                  : "当前网关处于开放模式，令牌为可选项"}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-zinc-200"
            aria-label="关闭弹窗"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-5">
          {reason && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-700 dark:text-amber-300">
              {reason}
            </div>
          )}

          <div className="space-y-1.5">
            <label
              htmlFor="neruton-admin-token-input"
              className="block text-xs font-medium text-zinc-700 dark:text-zinc-300"
            >
              NERUTON_AUTH_TOKEN
            </label>
            <div className="relative">
              <input
                id="neruton-admin-token-input"
                type={visible ? "text" : "password"}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="输入服务端配置的 Bearer Token..."
                autoFocus
                className="w-full rounded-xl border border-zinc-300 bg-zinc-50 py-2.5 pl-3.5 pr-10 font-mono text-xs text-zinc-900 placeholder:text-zinc-400 focus:border-cyan-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:bg-zinc-950"
              />
              <button
                type="button"
                onClick={() => setVisible((v) => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-1 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
                aria-label={visible ? "隐藏令牌" : "显示令牌"}
              >
                {visible ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
            <p className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
              令牌仅保存在当前浏览器的{" "}
              <code className="rounded bg-zinc-100 px-1 py-0.5 text-[10px] dark:bg-zinc-900">
                localStorage
              </code>{" "}
              中，用于执行断开隧道 (DELETE) 操作并在 CLI 快速启动命令中自动补全{" "}
              <code className="rounded bg-zinc-100 px-1 py-0.5 text-[10px] dark:bg-zinc-900">
                --token
              </code>
              。
            </p>
          </div>

          <div className="flex items-center justify-between pt-2">
            {token ? (
              <button
                type="button"
                onClick={() => {
                  onSave("");
                  onClose();
                }}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium text-rose-600 transition hover:bg-rose-500/10 dark:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                清除令牌
              </button>
            ) : (
              <span />
            )}

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-zinc-200 px-3.5 py-2 text-xs font-medium text-zinc-600 transition hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                取消
              </button>
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 px-4 py-2 text-xs font-semibold text-zinc-950 shadow-sm transition hover:brightness-110"
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                保存令牌
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
