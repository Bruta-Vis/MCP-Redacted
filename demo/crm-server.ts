/**
 * A stand-in for a customer's internal system: a small CRM / helpdesk MCP
 * server that returns raw PII, the way real internal tools do. The gateway
 * proxies it; nothing here knows the gateway exists.
 *
 * All data is fictitious (example.com addresses, 555-01xx numbers, test card numbers).
 */
import { MCPServer } from "mcp-use";
import { z } from "zod";

const customers = [
  {
    id: "c_1001",
    name: "Ada Lovelace",
    email: "ada.lovelace@example.com",
    phone: "(415) 555-0134",
    company: "Acme Health",
    address: "12 Analytical Way, San Francisco, CA",
    plan: "enterprise",
  },
  {
    id: "c_1002",
    name: "Grace Hopper",
    email: "grace@example.org",
    phone: "212-555-0187",
    company: "Northwind Clinics",
    address: "88 Compiler Ct, Arlington, VA",
    plan: "pro",
  },
  {
    id: "c_1003",
    name: "Alan Turing",
    email: "alan.t@example.net",
    phone: "+1 312 555 0102",
    company: "Acme Health",
    address: "7 Enigma Row, Chicago, IL",
    plan: "pro",
  },
];

const tickets = [
  {
    id: "T-481",
    customerId: "c_1001",
    subject: "Card declined on renewal",
    status: "open",
    body:
      "Customer called from (415) 555-0134. Says card 4111 1111 1111 1111 was declined twice. " +
      "Asked us to email the invoice to ada.lovelace@example.com. Login attempts came from 203.0.113.42.",
  },
  {
    id: "T-482",
    customerId: "c_1002",
    subject: "Identity verification",
    status: "pending",
    body:
      "Grace sent SSN 123-45-6789 in chat to verify identity (should not have). " +
      "Our engineer pasted a debug token AKIAIOSFODNN7EXAMPLE into the thread; rotate it.",
  },
];

const server = new MCPServer({
  name: "demo-crm",
  title: "Demo CRM",
  version: "1.0.0",
  description: "Fictitious CRM and helpdesk used to demonstrate the privacy gateway",
});

const json = (data: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  structuredContent: data as Record<string, unknown>,
});

server.tool(
  {
    name: "search_customers",
    title: "Search customers",
    description: "Search customers by name, email or company. Empty query lists everyone.",
    inputSchema: z.object({ query: z.string().default("").describe("Text to match") }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  async ({ query }) => {
    const q = query.toLowerCase();
    const found = customers.filter((c) =>
      [c.name, c.email, c.company].some((f) => f.toLowerCase().includes(q)),
    );
    return json({ customers: found });
  },
);

server.tool(
  {
    name: "lookup_customer_by_email",
    title: "Look up customer by email",
    description: "Exact email lookup. Returns the customer and their open tickets.",
    inputSchema: z.object({ email: z.string().describe("Customer email address") }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  async ({ email }) => {
    const customer = customers.find((c) => c.email.toLowerCase() === email.toLowerCase());
    if (!customer) throw new Error(`No customer with email ${email}`);
    return json({ customer, tickets: tickets.filter((t) => t.customerId === customer.id) });
  },
);

server.tool(
  {
    name: "get_ticket",
    title: "Get support ticket",
    description: "Fetch a support ticket, including its free-text body.",
    inputSchema: z.object({ id: z.string().describe("Ticket id, e.g. T-481") }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  async ({ id }) => {
    const ticket = tickets.find((t) => t.id === id);
    if (!ticket) throw new Error(`No ticket ${id}`);
    return json({ ticket });
  },
);

const port = Number(process.env.CRM_PORT ?? 3001);
await server.listen(port);
console.log(`demo-crm listening on http://localhost:${port}/mcp`);
