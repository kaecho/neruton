"use client";

import React, { useState } from "react";
import {
  CodeBlock,
  CopyButton,
  ModalDialog,
} from "@/components/GeistPrimitives";
import { createToken, resolveCliServerArg } from "@/lib/api";
import { parsePrefixList } from "@/lib/format";
import type { CreateTokenResponse, ServerInfo } from "@/lib/types";

interface CreateTokenModalProps {
  open: boolean;
  onClose: () => void;
  info: ServerInfo | null;
  onCreated: (created: CreateTokenResponse) => void;
}

export function CreateTokenModal({
  open,
  onClose,
  info,
  onCreated,
}: CreateTokenModalProps) {
  const [name, setName] = useState("");
  const [prefixesInput, setPrefixesInput] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreateTokenResponse | null>(null);

  const cliServer = resolveCliServerArg(info);

  const handleClose = () => {
    setName("");
    setPrefixesInput("");
    setError(null);
    setCreated(null);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("请输入令牌名称");
      return;
    }

    const parsedPrefixes = parsePrefixList(prefixesInput);
    setSubmitting(true);
    try {
      const res = await createToken({
        name: trimmedName,
        allowed_prefixes: parsedPrefixes.length > 0 ? parsedPrefixes : undefined,
      });
      setCreated(res);
      onCreated(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建令牌失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalDialog
      open={open}
      onClose={handleClose}
      preventBackdropClose={Boolean(created)}
      maxWidthClass={created ? "max-w-lg" : "max-w-md"}
      title={created ? "令牌已创建" : "创建隧道令牌"}
      description={
        created
          ? "密钥仅在此时显示一次，关闭弹窗后无法再次查看完整内容。"
          : "用于授权 neruton CLI 建立内网穿透隧道。"
      }
    >
      {created ? (
        <div className="space-y-4">
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs font-medium text-foreground">
                令牌密钥（{created.token.name}）
              </span>
              <CopyButton text={created.secret} label="复制密钥" />
            </div>
            <div className="overflow-x-auto rounded-md border border-border bg-surface px-3 py-2.5 font-mono text-xs text-foreground">
              {created.secret}
            </div>
          </div>

          <div className="space-y-2">
            <span className="block text-xs font-medium text-foreground">
              CLI 使用方式
            </span>
            <CodeBlock
              label="保存为默认配置"
              code={`neruton config set --token ${created.secret}`}
            />
            <CodeBlock
              label="直接命令行传入"
              code={`neruton tunnel --server ${cliServer} --url http://localhost:3000 --token ${created.secret}`}
            />
          </div>

          <div className="flex justify-end border-t border-border pt-4">
            <button
              type="button"
              onClick={handleClose}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90"
            >
              我已保存密钥
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label
              htmlFor="token-name"
              className="block text-xs font-medium text-foreground"
            >
              令牌名称
            </label>
            <input
              id="token-name"
              type="text"
              autoFocus
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如 MacBook Pro 或 CI Runner"
              className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="token-prefixes"
              className="block text-xs font-medium text-foreground"
            >
              允许的子域名前缀（可选）
            </label>
            <input
              id="token-prefixes"
              type="text"
              value={prefixesInput}
              onChange={(e) => setPrefixesInput(e.target.value)}
              placeholder="留空不限制；多个前缀用英文逗号分隔，如 app, staging"
              className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
            />
            <p className="text-[11px] text-secondary">
              设置前缀白名单后，该令牌仅允许注册指定子域名，且不允许随机 UUID。
            </p>
          </div>

          {error ? (
            <div
              role="alert"
              className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400"
            >
              {error}
            </div>
          ) : null}

          <div className="flex items-center justify-end gap-2 border-t border-border pt-4">
            <button
              type="button"
              onClick={handleClose}
              className="inline-flex h-8 items-center rounded-md border border-border bg-background px-3 text-xs text-secondary hover:text-foreground"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "创建中..." : "创建令牌"}
            </button>
          </div>
        </form>
      )}
    </ModalDialog>
  );
}
