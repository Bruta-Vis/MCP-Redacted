import { z } from "zod";
import { FIELD_KINDS, PATTERN_KINDS } from "./redact/types.js";
import type { RedactionPolicy } from "./redact/engine.js";

const httpUpstream = z.object({
  url: z.string().url(),
  authToken: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
});

const stdioUpstream = z.object({
  command: z.string(),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).optional(),
  cwd: z.string().optional(),
});

const upstreams = z.record(
  z.string().regex(/^[a-z][a-z0-9-]*$/, "namespace must be lowercase letters, digits and dashes"),
  z.union([httpUpstream, stdioUpstream]),
);

export type UpstreamConfig = z.infer<typeof upstreams>[string];

export interface GatewayConfig {
  upstreams: Record<string, UpstreamConfig>;
  policy: RedactionPolicy;
}

const ALL_KINDS = new Set<string>([...PATTERN_KINDS, ...FIELD_KINDS]);
const list = (v: string | undefined) =>
  (v ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * Configuration comes from environment variables so the same build runs on
 * Manufact Cloud, in a container, or in a customer's own VPC:
 *
 * - GATEWAY_UPSTREAMS        JSON: { "<namespace>": { "url": "...", "authToken": "..." } | { "command": "...", "args": [] } }
 * - GATEWAY_SENSITIVE_TERMS  comma-separated whole-word terms (account names, codenames)
 * - GATEWAY_ENABLED_KINDS    comma-separated kinds to redact; default is all
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const raw = env.GATEWAY_UPSTREAMS ?? JSON.stringify({ crm: { url: "http://localhost:3001/mcp" } });
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("GATEWAY_UPSTREAMS is not valid JSON");
  }
  const result = upstreams.safeParse(parsed);
  if (!result.success) throw new Error(`GATEWAY_UPSTREAMS is invalid: ${z.prettifyError(result.error)}`);

  const kinds = list(env.GATEWAY_ENABLED_KINDS);
  const unknown = kinds.filter((k) => !ALL_KINDS.has(k));
  if (unknown.length) throw new Error(`GATEWAY_ENABLED_KINDS has unknown kinds: ${unknown.join(", ")}`);

  return {
    upstreams: result.data,
    policy: {
      sensitiveTerms: list(env.GATEWAY_SENSITIVE_TERMS),
      ...(kinds.length > 0 && { enabledKinds: kinds as RedactionPolicy["enabledKinds"] }),
    },
  };
}
