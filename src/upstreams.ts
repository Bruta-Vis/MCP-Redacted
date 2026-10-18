import { MCPClient } from "@mcp-use/client";
import type { MCPServer } from "mcp-use";
import type { AuditLog } from "./audit.js";
import type { UpstreamConfig } from "./config.js";
import { createRedactingConnection } from "./redacting-connection.js";
import type { RedactionEngine } from "./redact/engine.js";

export interface UpstreamStatus {
  namespace: string;
  transport: "http" | "stdio";
  status: "connected" | "unavailable";
  tools: number;
  error?: string;
}

/**
 * Connect to each upstream, wrap it in the redacting connection, and mount it on
 * the gateway with `server.proxy()`. Upstream tools appear as `<namespace>_<tool>`.
 * An unreachable upstream is reported, not fatal, so one bad dependency can't
 * take the gateway down.
 */
export async function mountUpstreams(
  server: MCPServer<any, any>,
  upstreams: Record<string, UpstreamConfig>,
  deps: { engine: RedactionEngine; audit: AuditLog },
): Promise<UpstreamStatus[]> {
  const client = new MCPClient({
    mcpServers: Object.fromEntries(
      Object.entries(upstreams).map(([ns, cfg]) => [
        ns,
        // Gateway-to-upstream auth is configured explicitly; never open a browser OAuth flow from a server.
        "url" in cfg ? { ...cfg, oauth: false as const } : { ...cfg, stderr: "inherit" as const },
      ]),
    ),
  });

  // Dev hot reload re-evaluates the entry module; close the previous run's upstream connections.
  const holder = globalThis as { __gatewayUpstreamClient?: MCPClient };
  await holder.__gatewayUpstreamClient?.close().catch(() => {});
  holder.__gatewayUpstreamClient = client;

  const statuses: UpstreamStatus[] = [];
  for (const [namespace, cfg] of Object.entries(upstreams)) {
    const transport = "url" in cfg ? "http" : "stdio";
    try {
      const connection = await client.connect(namespace);
      const tools = await connection.listTools();
      await server.proxy(createRedactingConnection(connection as any, { namespace, ...deps }));
      statuses.push({ namespace, transport, status: "connected", tools: tools.length });
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      console.error(`[gateway] upstream "${namespace}" unavailable: ${error}`);
      statuses.push({ namespace, transport, status: "unavailable", tools: 0, error });
    }
  }

  const close = () => void client.close().catch(() => {});
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
  return statuses;
}
