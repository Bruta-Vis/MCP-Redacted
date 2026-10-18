import { describe, expect, it, vi } from "vitest";
import { AuditLog } from "../src/audit.js";
import { createRedactingConnection, type UpstreamConnection } from "../src/redacting-connection.js";
import { RedactionEngine } from "../src/redact/engine.js";
import { TokenVault } from "../src/redact/vault.js";

const CUSTOMER = { id: "c_1", name: "Ada Lovelace", email: "ada@example.com", plan: "pro" };

function fakeUpstream(overrides: Partial<UpstreamConnection> = {}): UpstreamConnection {
  return {
    info: { server: { name: "upstream-real-name" } },
    listTools: vi.fn(async () => [{ name: "get_customer", description: "Get a customer" }]),
    callTool: vi.fn(async (_name: string, args?: Record<string, unknown>) => ({
      content: [{ type: "text" as const, text: JSON.stringify(CUSTOMER) }],
      structuredContent: { customer: CUSTOMER, query: args },
    })),
    readResource: vi.fn(async (uri: string) => ({
      contents: [{ uri, text: "contact ada@example.com" }],
    })),
    listPrompts: vi.fn(async () => ({ prompts: [] })),
    getPrompt: vi.fn(async () => ({
      messages: [{ role: "user" as const, content: { type: "text" as const, text: "Email ada@example.com" } }],
    })),
    ...overrides,
  };
}

function setup(upstream = fakeUpstream()) {
  const engine = new RedactionEngine({}, new TokenVault());
  const audit = new AuditLog({ capacity: 50 });
  const conn = createRedactingConnection(upstream, { namespace: "crm", engine, audit });
  return { engine, audit, conn, upstream };
}

describe("createRedactingConnection", () => {
  it("uses the configured namespace instead of the upstream's own name", () => {
    expect(setup().conn.info.server?.name).toBe("crm");
  });

  it("redacts text and structured content on tool results", async () => {
    const { conn } = setup();
    const result = (await conn.callTool("get_customer", { id: "c_1" })) as any;
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("ada@example.com");
    expect(serialized).not.toContain("Ada Lovelace");
    expect(result.structuredContent.customer).toEqual({
      id: "c_1",
      name: "[PERSON_NAME_1]",
      email: "[EMAIL_1]",
      plan: "pro",
    });
    expect(JSON.parse(result.content[0].text).email).toBe("[EMAIL_1]");
  });

  it("rehydrates tokens in arguments before calling upstream", async () => {
    const { conn, upstream } = setup();
    await conn.callTool("get_customer", { id: "c_1" });
    await conn.callTool("lookup", { email: "[EMAIL_1]" });
    expect(upstream.callTool).toHaveBeenLastCalledWith(
      "lookup",
      { email: "ada@example.com" },
      undefined,
    );
  });

  it("records an audit entry without original values", async () => {
    const { conn, audit } = setup();
    await conn.callTool("get_customer", { id: "c_1" });
    const [entry] = audit.list();
    expect(entry).toMatchObject({
      upstream: "crm",
      operation: "tools/call",
      target: "get_customer",
      status: "ok",
    });
    expect(entry!.findings.length).toBeGreaterThan(0);
    expect(JSON.stringify(audit.list())).not.toContain("ada@example.com");
    expect(JSON.stringify(audit.list())).not.toContain("Ada Lovelace");
  });

  it("redacts PII inside upstream error messages", async () => {
    const { conn, audit } = setup(
      fakeUpstream({
        callTool: vi.fn(async () => {
          throw new Error("no account for ada@example.com");
        }),
      }),
    );
    await expect(conn.callTool("get_customer", {})).rejects.toThrow("no account for [EMAIL_1]");
    expect(audit.list()[0]!.status).toBe("error");
  });

  it("redacts resources and prompts", async () => {
    const { conn } = setup();
    const res = (await conn.readResource("crm://notes")) as any;
    expect(res.contents[0].text).toBe("contact [EMAIL_1]");
    const prompt = (await conn.getPrompt("p", {})) as any;
    expect(prompt.messages[0].content.text).toBe("Email [EMAIL_1]");
  });

  it("passes introspection calls straight through", async () => {
    const { conn, upstream } = setup();
    expect(await conn.listTools()).toEqual(await upstream.listTools());
  });
});

describe("AuditLog", () => {
  it("keeps the newest entries up to capacity and summarizes them", () => {
    const audit = new AuditLog({ capacity: 2 });
    for (const target of ["a", "b", "c"]) {
      audit.record({
        upstream: "crm",
        operation: "tools/call",
        target,
        status: "ok",
        latencyMs: 5,
        findings: [{ kind: "EMAIL", token: "[EMAIL_1]" }],
        rehydrated: 0,
        preview: "",
      });
    }
    expect(audit.list().map((e) => e.target)).toEqual(["c", "b"]);
    expect(audit.summary()).toMatchObject({ calls: 3, redactions: 3, byKind: { EMAIL: 3 } });
  });
});
