import { describe, expect, it } from "vitest";
import { RedactionEngine } from "../src/redact/engine.js";
import { TokenVault } from "../src/redact/vault.js";

const RAW = ["ada@example.com", "415-555-0134", "123-45-6789", "Ada Lovelace", "1 Analytical Way"];

function engine(opts: Partial<ConstructorParameters<typeof RedactionEngine>[0]> = {}) {
  return new RedactionEngine({ sensitiveTerms: ["Acme Health"], ...opts }, new TokenVault());
}

function containsRaw(value: unknown): string[] {
  const s = JSON.stringify(value);
  return RAW.filter((r) => s.includes(r));
}

describe("redactText", () => {
  it("replaces each detected value with a typed token", () => {
    const { text, findings } = engine().redactText("Email ada@example.com or call 415-555-0134");
    expect(text).toBe("Email [EMAIL_1] or call [PHONE_1]");
    expect(findings).toEqual([
      { kind: "EMAIL", token: "[EMAIL_1]" },
      { kind: "PHONE", token: "[PHONE_1]" },
    ]);
  });

  it("reuses the same token for the same value, normalized", () => {
    const e = engine();
    const a = e.redactText("ada@example.com").text;
    const b = e.redactText("ADA@Example.com and (415) 555-0134 / 415.555.0134").text;
    expect(a).toBe("[EMAIL_1]");
    expect(b).toBe("[EMAIL_1] and [PHONE_1] / [PHONE_1]");
  });

  it("never puts original values in findings", () => {
    const { findings } = engine().redactText("ssn 123-45-6789, Acme Health");
    expect(containsRaw(findings)).toEqual([]);
    expect(JSON.stringify(findings)).not.toContain("Acme Health");
  });

  it("respects the enabled kinds in the policy", () => {
    const { text } = engine({ enabledKinds: ["EMAIL"] }).redactText("ada@example.com 415-555-0134");
    expect(text).toBe("[EMAIL_1] 415-555-0134");
  });
});

describe("redactValue (structured content)", () => {
  it("redacts whole values under sensitive keys and patterns everywhere else", () => {
    const input = {
      customers: [
        {
          id: "c_1",
          name: "Ada Lovelace",
          address: "1 Analytical Way",
          notes: "prefers email: ada@example.com",
          plan: "pro",
        },
      ],
    };
    const { value, findings } = engine().redactValue(input);
    expect(value).toEqual({
      customers: [
        {
          id: "c_1",
          name: "[PERSON_NAME_1]",
          address: "[ADDRESS_1]",
          notes: "prefers email: [EMAIL_1]",
          plan: "pro",
        },
      ],
    });
    expect(findings.map((f) => f.path)).toEqual([
      "customers[0].name",
      "customers[0].address",
      "customers[0].notes",
    ]);
    expect(containsRaw(value)).toEqual([]);
  });

  it("matches sensitive keys regardless of case and separators", () => {
    const { value } = engine().redactValue({ FirstName: "Ada", last_name: "Lovelace", DOB: "1815-12-10" });
    expect(value).toEqual({
      FirstName: "[PERSON_NAME_1]",
      last_name: "[PERSON_NAME_2]",
      DOB: "[DATE_OF_BIRTH_1]",
    });
  });

  it("leaves non-string scalars alone and does not mutate the input", () => {
    const input = { age: 36, active: true, email: "ada@example.com" };
    const { value } = engine().redactValue(input);
    expect(value).toEqual({ age: 36, active: true, email: "[EMAIL_1]" });
    expect(input.email).toBe("ada@example.com");
  });
});

describe("redactToolText (JSON in text content)", () => {
  it("parses JSON text, redacts it structurally, and re-serializes", () => {
    const text = JSON.stringify({ name: "Ada Lovelace", email: "ada@example.com" });
    const out = engine().redactToolText(text);
    expect(JSON.parse(out.text)).toEqual({ name: "[PERSON_NAME_1]", email: "[EMAIL_1]" });
  });

  it("falls back to plain-text redaction for non-JSON", () => {
    expect(engine().redactToolText("{not json ada@example.com").text).toBe("{not json [EMAIL_1]");
  });
});

describe("rehydrate (tool arguments)", () => {
  it("swaps known tokens back to originals so upstream calls still work", () => {
    const e = engine();
    e.redactText("ada@example.com");
    const { value, count } = e.rehydrate({ email: "[EMAIL_1]", note: "re [EMAIL_1] and [EMAIL_9]" });
    expect(value).toEqual({ email: "ada@example.com", note: "re ada@example.com and [EMAIL_9]" });
    expect(count).toBe(2);
  });
});

describe("TokenVault limits", () => {
  it("evicts the oldest entries beyond capacity", () => {
    const vault = new TokenVault({ maxEntries: 2 });
    const t1 = vault.tokenFor("EMAIL", "a@example.com");
    vault.tokenFor("EMAIL", "b@example.com");
    vault.tokenFor("EMAIL", "c@example.com");
    expect(vault.resolve(t1)).toBeUndefined();
    expect(vault.size).toBe(2);
  });
});
