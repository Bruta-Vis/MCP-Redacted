// Rough per-payload cost of on-gateway redaction. Run: pnpm bench
import { RedactionEngine } from "../src/redact/engine.js";
import { TokenVault } from "../src/redact/vault.js";
const e = new RedactionEngine({ sensitiveTerms: ["Acme Health", "Northwind Clinics"] }, new TokenVault());
const ticket = { ticket: { id: "T-481", body: "Customer called from (415) 555-0134. Says card 4111 1111 1111 1111 was declined twice. Asked us to email the invoice to ada.lovelace@example.com. Login attempts came from 203.0.113.42." } };
const big = { customers: Array.from({ length: 200 }, (_, i) => ({ id: i, name: `Person ${i}`, email: `p${i}@example.com`, phone: "212-555-0187", company: "Acme Health", notes: "x".repeat(400) + " call 415-555-0134" })) };
for (const [label, payload] of [["ticket (~250 B)", ticket], ["200 customers (~110 KB)", big]] as const) {
  const text = JSON.stringify(payload);
  for (let i = 0; i < 50; i++) e.redactToolText(text);
  const n = label.startsWith("ticket") ? 5000 : 200; const t = performance.now();
  for (let i = 0; i < n; i++) e.redactToolText(text);
  console.log(label, (text.length/1024).toFixed(1)+"KB", ((performance.now() - t) / n).toFixed(3), "ms/op");
}
