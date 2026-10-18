import { isBuilding, MCPServer } from "mcp-use";
import { z } from "zod";
import { AuditLog } from "./src/audit.js";
import { loadConfig } from "./src/config.js";
import { RedactionEngine } from "./src/redact/engine.js";
import { FIELD_KINDS, PATTERN_KINDS } from "./src/redact/types.js";
import { TokenVault } from "./src/redact/vault.js";
import { mountUpstreams } from "./src/upstreams.js";

const config = loadConfig();
const engine = new RedactionEngine(config.policy, new TokenVault());
const audit = new AuditLog({ capacity: 500 });

const server = new MCPServer({
  name: "mcp-privacy-gateway",
  title: "Privacy Gateway",
  version: "0.1.0",
  description:
    "Proxies internal MCP servers and redacts PII, secrets and customer-specific terms on the gateway before results reach the model.",
  instructions: [
    "Tools prefixed with an upstream namespace (for example crm_search_customers) are proxied through a privacy gateway.",
    "Sensitive values in their results are replaced by placeholder tokens such as [EMAIL_1] or [PERSON_NAME_2].",
    "The same value always gets the same token, so you can compare and refer to them.",
    "Pass tokens unchanged as tool arguments (for example email: \"[EMAIL_1]\"); the gateway substitutes the real value before calling the upstream.",
    "Never ask the user to reveal the value behind a token. Use show-audit-log when the user asks what was redacted.",
  ].join(" "),
  websiteUrl: "https://github.com/mcp-use/mcp-use",
  icons: [{ src: "icon.svg", mimeType: "image/svg+xml", sizes: ["512x512"] }],
});

// ---- Shared schemas ---------------------------------------------------------

const kindSchema = z.enum([...PATTERN_KINDS, ...FIELD_KINDS]);

const findingSchema = z.object({
  kind: kindSchema,
  token: z.string().describe("Placeholder the model saw instead of the value"),
  path: z.string().optional().describe("JSON path for structured results"),
});

const auditEntrySchema = z.object({
  id: z.number(),
  at: z.string(),
  upstream: z.string(),
  operation: z.enum(["tools/call", "resources/read", "prompts/get", "preview"]),
  target: z.string(),
  status: z.enum(["ok", "error"]),
  latencyMs: z.number(),
  findings: z.array(findingSchema),
  rehydrated: z.number().describe("Tokens in the arguments swapped back to real values for the upstream"),
  preview: z.string().describe("Redacted payload as the model received it"),
});

const upstreamStatusSchema = z.object({
  namespace: z.string(),
  transport: z.enum(["http", "stdio"]),
  status: z.enum(["connected", "unavailable"]),
  tools: z.number(),
  error: z.string().optional(),
});

// ---- Gateway tools ----------------------------------------------------------

export const showAuditLog = server.tool(
  {
    name: "show-audit-log",
    title: "Show privacy audit log",
    description:
      "Show what the privacy gateway redacted from recent upstream calls: which kinds of data, which tokens, and the payload the model actually received. Never reveals original values.",
    inputSchema: z.object({
      limit: z.number().int().min(1).max(200).default(50).describe("How many recent calls to include"),
    }),
    outputSchema: z.object({
      summary: z.object({
        since: z.string(),
        calls: z.number(),
        errors: z.number(),
        redactions: z.number(),
        rehydrated: z.number(),
        byKind: z.record(z.string(), z.number()),
      }),
      upstreams: z.array(upstreamStatusSchema),
      entries: z.array(auditEntrySchema),
    }),
    view: {
      name: "audit-log",
      description: "Privacy audit trail for proxied tool calls",
      prefersBorder: true,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  async ({ limit }) => {
    const summary = audit.summary();
    const data = { summary, upstreams: upstreamStatuses, entries: audit.list(limit) };
    const kinds = Object.entries(summary.byKind)
      .map(([k, n]) => `${k} ×${n}`)
      .join(", ");
    return {
      content: [
        {
          type: "text",
          text:
            `${summary.calls} upstream calls audited since ${summary.since}; ` +
            `${summary.redactions} values redacted${kinds ? ` (${kinds})` : ""}; ` +
            `${summary.rehydrated} token${summary.rehydrated === 1 ? "" : "s"} rehydrated for upstream calls.`,
        },
      ],
      structuredContent: data,
    };
  },
);

export const previewRedaction = server.tool(
  {
    name: "preview-redaction",
    title: "Preview redaction",
    description:
      "Run the gateway's redaction policy over a piece of text and return the redacted version, to check what the policy catches.",
    inputSchema: z.object({ text: z.string().describe("Text to redact") }),
    outputSchema: z.object({ redacted: z.string(), findings: z.array(findingSchema) }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  async ({ text }) => {
    const started = performance.now();
    const { text: redacted, findings } = engine.redactText(text);
    audit.record({
      upstream: "gateway",
      operation: "preview",
      target: "preview-redaction",
      status: "ok",
      latencyMs: performance.now() - started,
      findings,
      rehydrated: 0,
      preview: redacted,
    });
    return { content: [{ type: "text", text: redacted }], structuredContent: { redacted, findings } };
  },
);

// ---- Upstreams ----------------------------------------------------------------
// Must be mounted before the server starts listening. `mcp-use build` evaluates
// this module to check views but serves nothing, so skip connecting there.
const upstreamStatuses = isBuilding()
    ? []
    : await mountUpstreams(server, config.upstreams, { engine, audit });

export default server;
