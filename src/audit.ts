import type { Finding, PiiKind } from "./redact/types.js";

export type AuditOperation = "tools/call" | "resources/read" | "prompts/get" | "preview";

export interface AuditEntry {
  id: number;
  at: string;
  upstream: string;
  operation: AuditOperation;
  /** Tool, resource URI or prompt name. */
  target: string;
  status: "ok" | "error";
  latencyMs: number;
  /** Kinds and tokens only; original values are never recorded. */
  findings: Finding[];
  /** How many tokens in the model's arguments were swapped back to real values for the upstream call. */
  rehydrated: number;
  /** Start of the redacted payload exactly as the model received it. */
  preview: string;
}

export interface AuditSummary {
  since: string;
  calls: number;
  errors: number;
  redactions: number;
  rehydrated: number;
  byKind: Partial<Record<PiiKind, number>>;
}

const MAX_FINDINGS_PER_ENTRY = 200;
const MAX_PREVIEW_CHARS = 600;

/**
 * Bounded in-memory audit trail. Totals cover every call since start; `list()`
 * returns the most recent `capacity` entries. Swap for an append-only store or
 * an OpenTelemetry exporter in production.
 */
export class AuditLog {
  private readonly entries: AuditEntry[] = [];
  private readonly capacity: number;
  private nextId = 1;
  private readonly totals: AuditSummary = {
    since: new Date().toISOString(),
    calls: 0,
    errors: 0,
    redactions: 0,
    rehydrated: 0,
    byKind: {},
  };

  constructor(opts: { capacity?: number } = {}) {
    this.capacity = opts.capacity ?? 500;
  }

  record(input: Omit<AuditEntry, "id" | "at">): AuditEntry {
    const entry: AuditEntry = {
      ...input,
      id: this.nextId++,
      at: new Date().toISOString(),
      latencyMs: Math.round(input.latencyMs * 10) / 10,
      findings: input.findings.slice(0, MAX_FINDINGS_PER_ENTRY),
      preview: input.preview.slice(0, MAX_PREVIEW_CHARS),
    };
    this.entries.push(entry);
    if (this.entries.length > this.capacity) this.entries.shift();

    this.totals.calls++;
    if (entry.status === "error") this.totals.errors++;
    this.totals.redactions += input.findings.length;
    this.totals.rehydrated += input.rehydrated;
    for (const f of input.findings) this.totals.byKind[f.kind] = (this.totals.byKind[f.kind] ?? 0) + 1;
    return entry;
  }

  /** Newest first. */
  list(limit = this.capacity): AuditEntry[] {
    return this.entries.slice(-limit).reverse();
  }

  summary(): AuditSummary {
    return { ...this.totals, byKind: { ...this.totals.byKind } };
  }
}
