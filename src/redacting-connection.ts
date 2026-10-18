import type { CallToolResult, GetPromptResult, InputRequiredResult, ReadResourceResult } from "mcp-use";
import type { AuditLog, AuditOperation } from "./audit.js";
import type { RedactionEngine } from "./redact/engine.js";
import type { Finding } from "./redact/types.js";

type RequestOptions = { signal?: AbortSignal; onprogress?: (p: { progress: number; total?: number; message?: string }) => void };

/**
 * The structural connection shape `MCPServer.proxy()` accepts. An
 * `@mcp-use/client` `MCPConnection` satisfies it, and so does the wrapper below,
 * so the gateway slots between the two without either side knowing.
 */
export interface UpstreamConnection {
  readonly info: { server?: { name: string } };
  supports?(capability: string): boolean;
  listTools(): Promise<any[]>;
  callTool(name: string, args?: Record<string, unknown>, options?: RequestOptions): Promise<CallToolResult | InputRequiredResult>;
  listAllResources?(): Promise<{ resources: any[] }>;
  listResources?(): Promise<{ resources: any[] }>;
  readResource(uri: string, options?: RequestOptions): Promise<ReadResourceResult>;
  listPrompts(): Promise<{ prompts: any[] }>;
  getPrompt(name: string, args: Record<string, unknown>, options?: RequestOptions): Promise<GetPromptResult>;
}

export interface RedactingConnectionOptions {
  /** Prefix for mounted capabilities, e.g. `crm` → `crm_search_customers`. */
  namespace: string;
  engine: RedactionEngine;
  audit: AuditLog;
}

/** Wraps an upstream so every payload headed for the model is redacted and every call is audited. */
export function createRedactingConnection(
  upstream: UpstreamConnection,
  { namespace, engine, audit }: RedactingConnectionOptions,
): UpstreamConnection {
  async function audited<T>(
    operation: AuditOperation,
    target: string,
    rehydrated: number,
    run: () => Promise<T>,
    redact: (raw: T) => { value: T; findings: Finding[]; preview: string; isError?: boolean },
  ): Promise<T> {
    const started = performance.now();
    try {
      const { value, findings, preview, isError } = redact(await run());
      audit.record({
        upstream: namespace,
        operation,
        target,
        status: isError ? "error" : "ok",
        latencyMs: performance.now() - started,
        findings,
        rehydrated,
        preview,
      });
      return value;
    } catch (err) {
      // Upstream error messages routinely echo inputs back; they reach the model too.
      const message = err instanceof Error ? err.message : String(err);
      const { text, findings } = engine.redactText(message);
      audit.record({
        upstream: namespace,
        operation,
        target,
        status: "error",
        latencyMs: performance.now() - started,
        findings,
        rehydrated,
        preview: text,
      });
      throw new Error(text);
    }
  }

  const wrapper: UpstreamConnection = {
    info: { server: { name: namespace } },

    // Introspection passes through untouched. Tool descriptions are a natural
    // place to add prompt-injection scanning later.
    listTools: () => upstream.listTools(),
    listPrompts: () => upstream.listPrompts(),

    callTool(name, args, options) {
      const { value: realArgs, count } = engine.rehydrate(args ?? {});
      return audited(
        "tools/call",
        name,
        count,
        () => upstream.callTool(name, realArgs, options),
        (raw) => {
          if (!("content" in raw) || !Array.isArray(raw.content)) {
            return { value: raw, findings: [], preview: "(input required)" };
          }
          const findings: Finding[] = [];
          const texts: string[] = [];
          const content = raw.content.map((block: any) => {
            if (block.type === "text" && typeof block.text === "string") {
              const r = engine.redactToolText(block.text);
              findings.push(...r.findings);
              texts.push(r.text);
              return { ...block, text: r.text };
            }
            if (block.type === "resource" && typeof block.resource?.text === "string") {
              const r = engine.redactToolText(block.resource.text);
              findings.push(...r.findings);
              texts.push(r.text);
              return { ...block, resource: { ...block.resource, text: r.text } };
            }
            // Images, audio and blobs pass through; OCR/transcription redaction is out of scope for the MVP.
            return block;
          });
          let structuredContent = raw.structuredContent;
          if (structuredContent !== undefined) {
            const r = engine.redactValue(structuredContent);
            structuredContent = r.value;
            // Structured content usually mirrors the text block; count each sensitive value once.
            if (findings.length === 0) findings.push(...r.findings);
          }
          return {
            value: { ...raw, content, ...(structuredContent !== undefined && { structuredContent }) } as CallToolResult,
            findings,
            preview: texts.join("\n"),
            isError: raw.isError === true,
          };
        },
      );
    },

    readResource(uri, options) {
      return audited(
        "resources/read",
        uri,
        0,
        () => upstream.readResource(uri, options),
        (raw) => {
          const findings: Finding[] = [];
          const texts: string[] = [];
          const contents = raw.contents.map((c: any) => {
            if (typeof c.text !== "string") return c;
            const r = engine.redactToolText(c.text);
            findings.push(...r.findings);
            texts.push(r.text);
            return { ...c, text: r.text };
          });
          return { value: { ...raw, contents }, findings, preview: texts.join("\n") };
        },
      );
    },

    getPrompt(name, args, options) {
      const { value: realArgs, count } = engine.rehydrate(args);
      return audited(
        "prompts/get",
        name,
        count,
        () => upstream.getPrompt(name, realArgs, options),
        (raw) => {
          const findings: Finding[] = [];
          const texts: string[] = [];
          const redactBlock = (block: any) => {
            if (block?.type !== "text" || typeof block.text !== "string") return block;
            const r = engine.redactText(block.text);
            findings.push(...r.findings);
            texts.push(r.text);
            return { ...block, text: r.text };
          };
          const messages = raw.messages.map((m: any) => ({
            ...m,
            content: Array.isArray(m.content) ? m.content.map(redactBlock) : redactBlock(m.content),
          }));
          return { value: { ...raw, messages }, findings, preview: texts.join("\n") };
        },
      );
    },
  };

  if (upstream.supports) wrapper.supports = (c) => upstream.supports!(c);
  if (upstream.listAllResources) wrapper.listAllResources = () => upstream.listAllResources!();
  if (upstream.listResources) wrapper.listResources = () => upstream.listResources!();
  return wrapper;
}
