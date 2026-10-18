import type { PiiKind } from "./types.js";

export const TOKEN_PATTERN = /\[([A-Z]+(?:_[A-Z]+)*)_(\d+)\]/g;

function normalize(kind: PiiKind, value: string): string {
  switch (kind) {
    case "PHONE": {
      const digits = value.replace(/\D/g, "");
      return digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
    }
    case "CREDIT_CARD":
    case "SSN":
      return value.replace(/\D/g, "");
    default:
      return value.trim().toLowerCase();
  }
}

export interface TokenVaultOptions {
  /** Upper bound on remembered values; the oldest are forgotten first. */
  maxEntries?: number;
}

/**
 * Maps sensitive values to stable placeholder tokens (`[EMAIL_1]`) so the model
 * can still reason about identity ("the same customer appears twice") without
 * seeing the value, and so tokens it sends back can be swapped for originals
 * before reaching the upstream server.
 *
 * Lives in process memory. On a stateless or multi-instance deployment it
 * belongs in per-session storage (e.g. a Durable Object keyed by session).
 */
export class TokenVault {
  private readonly byKey = new Map<string, string>(); // `${kind}:${normalized}` -> token
  private readonly byToken = new Map<string, { key: string; value: string }>();
  private readonly counters = new Map<PiiKind, number>();
  private readonly maxEntries: number;

  constructor(opts: TokenVaultOptions = {}) {
    this.maxEntries = opts.maxEntries ?? 10_000;
  }

  get size(): number {
    return this.byToken.size;
  }

  tokenFor(kind: PiiKind, value: string): string {
    const key = `${kind}:${normalize(kind, value)}`;
    const existing = this.byKey.get(key);
    if (existing) return existing;

    const n = (this.counters.get(kind) ?? 0) + 1;
    this.counters.set(kind, n);
    const token = `[${kind}_${n}]`;
    this.byKey.set(key, token);
    this.byToken.set(token, { key, value });

    while (this.byToken.size > this.maxEntries) {
      const [oldest, entry] = this.byToken.entries().next().value!;
      this.byToken.delete(oldest);
      this.byKey.delete(entry.key);
    }
    return token;
  }

  resolve(token: string): string | undefined {
    return this.byToken.get(token)?.value;
  }
}
