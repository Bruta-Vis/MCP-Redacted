import { describe, expect, it } from "vitest";
import { detectAll, luhnValid } from "../src/redact/detectors.js";
import { TermTrie } from "../src/redact/trie.js";

const kinds = (text: string) => detectAll(text).map((m) => [m.kind, m.value]);

describe("email", () => {
  it("finds plain and plus-addressed emails", () => {
    expect(kinds("mail ada@example.com or ada+billing@sub.example.co.uk")).toEqual([
      ["EMAIL", "ada@example.com"],
      ["EMAIL", "ada+billing@sub.example.co.uk"],
    ]);
  });

  it("ignores things that only look like handles", () => {
    expect(kinds("ping @ada on slack, or user@localhost")).toEqual([]);
  });
});

describe("phone (NANP)", () => {
  it.each([
    "(415) 555-0134",
    "415-555-0134",
    "415.555.0134",
    "+1 415 555 0134",
    "1-415-555-0134",
  ])("finds %s", (phone) => {
    expect(kinds(`call ${phone} today`)).toEqual([["PHONE", phone]]);
  });

  it("does not flag order numbers or years", () => {
    expect(kinds("order 2026 shipped, ref 12345, version 1.2.3")).toEqual([]);
  });
});

describe("SSN", () => {
  it("finds a dashed SSN", () => {
    expect(kinds("ssn 123-45-6789")).toEqual([["SSN", "123-45-6789"]]);
  });

  it.each(["000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567", "123-45-0000"])(
    "rejects invalid range %s",
    (ssn) => {
      expect(kinds(ssn).filter(([k]) => k === "SSN")).toEqual([]);
    },
  );
});

describe("credit card", () => {
  it("validates the Luhn checksum", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });

  it("finds spaced and dashed cards that pass Luhn", () => {
    expect(kinds("card 4111 1111 1111 1111 and 5500-0000-0000-0004")).toEqual([
      ["CREDIT_CARD", "4111 1111 1111 1111"],
      ["CREDIT_CARD", "5500-0000-0000-0004"],
    ]);
  });

  it("ignores long digit runs that fail Luhn", () => {
    expect(kinds("tracking 4111111111111112")).toEqual([]);
  });
});

describe("IPv4", () => {
  it("finds valid addresses only", () => {
    expect(kinds("from 10.0.12.7 not 999.1.1.1")).toEqual([["IP_ADDRESS", "10.0.12.7"]]);
  });
});

describe("secrets", () => {
  it("finds AWS access key ids", () => {
    expect(kinds("key AKIAIOSFODNN7EXAMPLE leaked")).toEqual([
      ["SECRET", "AKIAIOSFODNN7EXAMPLE"],
    ]);
  });

  it("finds JWTs", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(kinds(`Bearer ${jwt}`)).toEqual([["SECRET", jwt]]);
  });
});

describe("performance guards", () => {
  it("stays linear on long runs of word characters (no catastrophic email backtracking)", () => {
    const text = `${"x".repeat(50_000)} ada@example.com`;
    const started = performance.now();
    expect(detectAll(text).map((m) => m.kind)).toEqual(["EMAIL"]);
    expect(performance.now() - started).toBeLessThan(250);
  });
});

describe("overlap resolution", () => {
  it("returns non-overlapping matches in order", () => {
    const matches = detectAll("a@example.com 415-555-0134 123-45-6789");
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i]!.start).toBeGreaterThanOrEqual(matches[i - 1]!.end);
    }
    expect(matches.map((m) => m.kind)).toEqual(["EMAIL", "PHONE", "SSN"]);
  });
});

describe("TermTrie", () => {
  const trie = new TermTrie(["Project Falcon", "Acme Health", "Ada Lovelace"]);

  it("matches configured terms case-insensitively on word boundaries", () => {
    const found = trie.find("acme health signed; see PROJECT FALCON notes");
    expect(found.map((m) => m.value)).toEqual(["acme health", "PROJECT FALCON"]);
    expect(found.every((m) => m.kind === "TERM")).toBe(true);
  });

  it("does not match inside larger words", () => {
    expect(trie.find("Acme Healthcare and AdaLovelace")).toEqual([]);
  });

  it("prefers the longest term at a position", () => {
    const t = new TermTrie(["Ada", "Ada Lovelace"]);
    expect(t.find("Ada Lovelace wrote").map((m) => m.value)).toEqual(["Ada Lovelace"]);
  });

  it("is merged into detectAll when supplied", () => {
    expect(detectAll("Ada Lovelace <ada@example.com>", { terms: trie }).map((m) => m.kind)).toEqual([
      "TERM",
      "EMAIL",
    ]);
  });
});
