import { detectAll } from "./detectors.js";
import { TermTrie } from "./trie.js";
import { PATTERN_KINDS, type Finding, type PatternKind, type PiiKind } from "./types.js";
import { TOKEN_PATTERN, type TokenVault } from "./vault.js";

/** JSON keys whose values are redacted wholesale, matched after lowercasing and stripping `_`, `-`, spaces. */
export const DEFAULT_SENSITIVE_KEYS: Record<string, PiiKind> = {
  name: "PERSON_NAME",
  fullname: "PERSON_NAME",
  firstname: "PERSON_NAME",
  middlename: "PERSON_NAME",
  lastname: "PERSON_NAME",
  givenname: "PERSON_NAME",
  familyname: "PERSON_NAME",
  surname: "PERSON_NAME",
  contactname: "PERSON_NAME",
  customername: "PERSON_NAME",
  address: "ADDRESS",
  streetaddress: "ADDRESS",
  street: "ADDRESS",
  addressline1: "ADDRESS",
  addressline2: "ADDRESS",
  homeaddress: "ADDRESS",
  mailingaddress: "ADDRESS",
  billingaddress: "ADDRESS",
  shippingaddress: "ADDRESS",
  dob: "DATE_OF_BIRTH",
  dateofbirth: "DATE_OF_BIRTH",
  birthdate: "DATE_OF_BIRTH",
  birthday: "DATE_OF_BIRTH",
  email: "EMAIL",
  emailaddress: "EMAIL",
  phone: "PHONE",
  phonenumber: "PHONE",
  mobile: "PHONE",
  telephone: "PHONE",
  ssn: "SSN",
  socialsecuritynumber: "SSN",
};

export interface RedactionPolicy {
  /** Kinds to redact. Defaults to every kind. */
  enabledKinds?: readonly PiiKind[];
  /** Customer-specific dictionary (account names, codenames) matched as whole words. */
  sensitiveTerms?: readonly string[];
  /** Extra or overriding key → kind mappings; map a key to `null` to stop treating it as sensitive. */
  sensitiveKeys?: Record<string, PiiKind | null>;
}

export interface Redacted<T> {
  value: T;
  findings: Finding[];
}

const normalizeKey = (k: string) => k.toLowerCase().replace(/[\s_-]/g, "");

/**
 * Deterministic, on-box redaction. Nothing here calls a model or the network,
 * so it is cheap enough to run on every tool result and auditable line by line.
 */
export class RedactionEngine {
  private readonly enabled: ReadonlySet<PiiKind>;
  private readonly patternKinds: ReadonlySet<PatternKind>;
  private readonly terms: TermTrie;
  private readonly keys: Map<string, PiiKind>;

  constructor(policy: RedactionPolicy, private readonly vault: TokenVault) {
    this.enabled = new Set(policy.enabledKinds ?? [...PATTERN_KINDS, "PERSON_NAME", "ADDRESS", "DATE_OF_BIRTH"]);
    this.patternKinds = new Set(PATTERN_KINDS.filter((k) => this.enabled.has(k)));
    this.terms = new TermTrie(policy.sensitiveTerms ?? []);
    this.keys = new Map();
    for (const [k, kind] of Object.entries({ ...DEFAULT_SENSITIVE_KEYS, ...policy.sensitiveKeys })) {
      if (kind) this.keys.set(normalizeKey(k), kind);
    }
  }

  redactText(text: string, path?: string): { text: string; findings: Finding[] } {
    const matches = detectAll(text, { terms: this.terms, kinds: this.patternKinds });
    if (matches.length === 0) return { text, findings: [] };

    const findings: Finding[] = [];
    let out = "";
    let cursor = 0;
    for (const m of matches) {
      const token = this.vault.tokenFor(m.kind, m.value);
      out += text.slice(cursor, m.start) + token;
      cursor = m.end;
      findings.push(path === undefined ? { kind: m.kind, token } : { kind: m.kind, token, path });
    }
    return { text: out + text.slice(cursor), findings };
  }

  /** Deep-copies `value`, redacting sensitive keys wholesale and patterns in every other string. */
  redactValue<T>(value: T): Redacted<T> {
    const findings: Finding[] = [];
    const walk = (v: unknown, path: string, forced: PiiKind | undefined): unknown => {
      if (typeof v === "string" || ((typeof v === "number" || typeof v === "bigint") && forced)) {
        if (forced) {
          if (typeof v === "string" && v.trim() === "") return v;
          const token = this.vault.tokenFor(forced, String(v));
          findings.push({ kind: forced, token, path });
          return token;
        }
        const r = this.redactText(v as string, path);
        findings.push(...r.findings);
        return r.text;
      }
      if (Array.isArray(v)) return v.map((item, i) => walk(item, `${path}[${i}]`, forced));
      if (v && typeof v === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, child] of Object.entries(v)) {
          const keyKind = this.keys.get(normalizeKey(k));
          const kind = forced ?? (keyKind && this.enabled.has(keyKind) ? keyKind : undefined);
          out[k] = walk(child, path ? `${path}.${k}` : k, kind);
        }
        return out;
      }
      return v;
    };
    return { value: walk(value, "", undefined) as T, findings };
  }

  /** Tool text content is often serialized JSON; redact it structurally when it parses. */
  redactToolText(text: string): { text: string; findings: Finding[] } {
    const trimmed = text.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        const { value, findings } = this.redactValue(parsed);
        return { text: JSON.stringify(value, null, text.includes("\n") ? 2 : undefined), findings };
      } catch {
        // Not JSON; fall through to plain text.
      }
    }
    return this.redactText(text);
  }

  /** Swap tokens the model sends back for their original values. Unknown tokens are left as-is. */
  rehydrate<T>(value: T): { value: T; count: number } {
    let count = 0;
    const walk = (v: unknown): unknown => {
      if (typeof v === "string") {
        return v.replace(TOKEN_PATTERN, (token) => {
          const original = this.vault.resolve(token);
          if (original === undefined) return token;
          count++;
          return original;
        });
      }
      if (Array.isArray(v)) return v.map(walk);
      if (v && typeof v === "object") {
        return Object.fromEntries(Object.entries(v).map(([k, child]) => [k, walk(child)]));
      }
      return v;
    };
    return { value: walk(value) as T, count };
  }
}
