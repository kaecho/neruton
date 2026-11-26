"use client";

import React, { useEffect, useState } from "react";
import { Check, Copy, X } from "lucide-react";
import { copyToClipboard } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

/* ── Accessible Geist Toggle Switch ──────────────────────────────── */

interface SwitchProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label: string;
}

export function Switch({ checked, onChange, disabled, label }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-foreground disabled:cursor-not-allowed disabled:opacity-45 ${
        checked
          ? "border-foreground bg-foreground"
          : "border-border-strong bg-muted"
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-3.5 w-3.5 rounded-full transition-transform ${
          checked
            ? "translate-x-4 bg-background"
            : "translate-x-0.5 bg-foreground"
        }`}
      />
    </button>
  );
}

/* ── Restrained 6px Status Dot ───────────────────────────────────── */

type DotTone = "online" | "warn" | "error" | "muted";

const DOT_TONES: Record<DotTone, string> = {
  online: "bg-emerald-500",
  warn: "bg-amber-500",
  error: "bg-red-500",
  muted: "bg-neutral-400 dark:bg-neutral-600",
};

export function StatusDot({ tone = "online" }: { tone?: DotTone }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${DOT_TONES[tone]}`}
    />
  );
}

/* ── Copy Button ─────────────────────────────────────────────────── */

interface CopyButtonProps {
  text: string;
  label?: string;
  copiedLabel?: string;
  iconOnly?: boolean;
  className?: string;
}

export function CopyButton({
  text,
  label,
  copiedLabel,
  iconOnly = false,
  className = "",
}: CopyButtonProps) {
  const { messages } = useI18n();
  const [copied, setCopied] = useState(false);

  const resolvedLabel = label ?? messages.common.copy;
  const resolvedCopiedLabel = copiedLabel ?? messages.common.copied;

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? resolvedCopiedLabel : resolvedLabel}
      aria-label={copied ? resolvedCopiedLabel : resolvedLabel}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md border border-border bg-background text-xs font-medium text-secondary transition-colors hover:border-border-strong hover:text-foreground ${
        iconOnly ? "h-7 w-7" : "h-7 px-2.5"
      } ${className}`}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      {!iconOnly ? (
        <span>{copied ? resolvedCopiedLabel : resolvedLabel}</span>
      ) : null}
    </button>
  );
}

/* ── Monospace Copyable Code Block ───────────────────────────────── */

interface CodeBlockProps {
  code: string;
  label?: string;
  prompt?: boolean;
}

export function CodeBlock({ code, label, prompt = true }: CodeBlockProps) {
  return (
    <div className="overflow-hidden rounded-md border border-border bg-surface">
      {label ? (
        <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
          <span className="font-mono text-[11px] text-secondary">{label}</span>
          <CopyButton text={code} />
        </div>
      ) : null}
      <div className="flex items-center justify-between gap-3 px-3 py-2.5">
        <div className="min-w-0 flex-1 overflow-x-auto">
          <code className="block whitespace-pre font-mono text-xs text-foreground">
            {prompt ? (
              <span className="select-none text-tertiary">$ </span>
            ) : null}
            {code}
          </code>
        </div>
        {!label ? <CopyButton text={code} iconOnly /> : null}
      </div>
    </div>
  );
}

/* ── Geist Modal Dialog ──────────────────────────────────────────── */

interface ModalDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  preventBackdropClose?: boolean;
  maxWidthClass?: string;
}

export function ModalDialog({
  open,
  onClose,
  title,
  description,
  children,
  preventBackdropClose = false,
  maxWidthClass = "max-w-md",
}: ModalDialogProps) {
  const { messages } = useI18n();

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !preventBackdropClose) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose, preventBackdropClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      onClick={() => {
        if (!preventBackdropClose) onClose();
      }}
    >
      <div
        className={`w-full ${maxWidthClass} overflow-hidden rounded-lg border border-border bg-background`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            <h2
              id="modal-title"
              className="text-sm font-semibold tracking-tight text-foreground"
            >
              {title}
            </h2>
            {description ? (
              <p className="mt-1 text-xs text-secondary">{description}</p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={messages.common.closeDialog}
            className="rounded-md p-1 text-secondary transition-colors hover:bg-muted hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}
