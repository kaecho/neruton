"use client";

import React from "react";
import { useI18n, type Locale } from "@/lib/i18n";

interface LocaleSwitcherProps {
  className?: string;
}

const OPTIONS: readonly { id: Locale; label: string }[] = [
  { id: "en", label: "EN" },
  { id: "zh", label: "中文" },
];

export function LocaleSwitcher({ className = "" }: LocaleSwitcherProps) {
  const { locale, setLocale, messages } = useI18n();

  return (
    <div
      role="group"
      aria-label={messages.common.switchLanguage}
      className={`inline-flex h-8 shrink-0 items-center rounded-md border border-border bg-surface p-0.5 text-[11px] ${className}`}
    >
      {OPTIONS.map((opt) => {
        const active = locale === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            onClick={() => setLocale(opt.id)}
            aria-pressed={active}
            className={`inline-flex h-full items-center justify-center rounded px-2 font-medium transition-colors ${
              active
                ? "bg-background text-foreground"
                : "text-secondary hover:text-foreground"
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
