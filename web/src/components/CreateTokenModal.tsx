"use client";

import React, { useState } from "react";
import {
  CodeBlock,
  CopyButton,
  ModalDialog,
} from "@/components/GeistPrimitives";
import { createToken, resolveCliServerArg } from "@/lib/api";
import { parsePrefixList } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
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
  const { messages } = useI18n();
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
      setError(messages.tokens.modalNameRequired);
      return;
    }

    const parsedPrefixes = parsePrefixList(prefixesInput);
    setSubmitting(true);
    try {
      const res = await createToken({
        name: trimmedName,
        allowed_prefixes:
          parsedPrefixes.length > 0 ? parsedPrefixes : undefined,
      });
      setCreated(res);
      onCreated(res);
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : messages.tokens.modalCreateFailed,
      );
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
      title={
        created
          ? messages.tokens.modalTitleCreated
          : messages.tokens.modalTitleCreate
      }
      description={
        created
          ? messages.tokens.modalDescCreated
          : messages.tokens.modalDescCreate
      }
    >
      {created ? (
        <div className="space-y-4">
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs font-medium text-foreground">
                {messages.tokens.modalSecretLabel(created.token.name)}
              </span>
              <CopyButton
                text={created.secret}
                label={messages.common.copySecret}
              />
            </div>
            <div className="overflow-x-auto rounded-md border border-border bg-surface px-3 py-2.5 font-mono text-xs text-foreground">
              {created.secret}
            </div>
          </div>

          <div className="space-y-2">
            <span className="block text-xs font-medium text-foreground">
              {messages.tokens.modalCliUsage}
            </span>
            <CodeBlock
              label={messages.tokens.modalSaveAsDefault}
              code={`neruton config set --token ${created.secret}`}
            />
            <CodeBlock
              label={messages.tokens.modalPassInline}
              code={`neruton tunnel --server ${cliServer} --url http://localhost:3000 --token ${created.secret}`}
            />
          </div>

          <div className="flex justify-end border-t border-border pt-4">
            <button
              type="button"
              onClick={handleClose}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90"
            >
              {messages.tokens.modalSavedDone}
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
              {messages.tokens.modalNameLabel}
            </label>
            <input
              id="token-name"
              type="text"
              autoFocus
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={messages.tokens.modalNamePlaceholder}
              className="h-9 w-full rounded-md border border-border bg-background px-3 text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="token-prefixes"
              className="block text-xs font-medium text-foreground"
            >
              {messages.tokens.modalPrefixesLabel}
            </label>
            <input
              id="token-prefixes"
              type="text"
              value={prefixesInput}
              onChange={(e) => setPrefixesInput(e.target.value)}
              placeholder={messages.tokens.modalPrefixesPlaceholder}
              className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground placeholder:text-tertiary focus:border-foreground focus:outline-none"
            />
            <p className="text-[11px] text-secondary">
              {messages.tokens.modalPrefixesHint}
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
              {messages.common.cancel}
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex h-8 items-center rounded-md bg-foreground px-4 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting
                ? messages.common.creating
                : messages.tokens.modalSubmitCreate}
            </button>
          </div>
        </form>
      )}
    </ModalDialog>
  );
}
