import type { TermTrie } from "./trie.js";
import type { Match, PatternKind } from "./types.js";

interface Detector {
  kind: PatternKind;
  pattern: RegExp;
  /** Optional post-filter for checks a regex can't express (checksums). */
  accept?: (value: string) => boolean;
}

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";

/**
 * Ordered by priority: when two detectors claim overlapping spans, the earlier
 * one wins (a 16-digit card beats a phone-shaped substring of it).
 */
const DETECTORS: Detector[] = [
  {
    kind: "SECRET",
    pattern: new RegExp(
      [
        "\\beyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", // JWT
        "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b", // AWS access key id
        "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b", // GitHub token
        "\\bxox[abprs]-[A-Za-z0-9-]{10,}", // Slack token
        "\\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", // LLM provider keys
      ].join("|"),
      "g",
    ),
  },
  {
    kind: "CREDIT_CARD",
    pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    accept: (v) => {
      const digits = v.replace(/\D/g, "");
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
    },
  },
  {
    kind: "SSN",
    pattern: /(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g,
  },
  {
    kind: "EMAIL",
    // The lookbehind anchors the local part at a word start; without it, long runs
    // of word characters with no "@" make the scan quadratic.
    pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g,
  },
  {
    kind: "IP_ADDRESS",
    pattern: new RegExp(`(?<!\\d)(?<!\\d\\.)(?:${OCTET}\\.){3}${OCTET}(?!\\d|\\.\\d)`, "g"),
  },
  {
    kind: "PHONE",
    // NANP: area code and exchange can't start with 0 or 1.
    pattern: /(?<![\w+])(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-]?[2-9]\d{2}[\s.-]?\d{4}(?!\w)/g,
  },
];

export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return digits.length > 0 && sum % 10 === 0;
}

export interface DetectOptions {
  /** Customer-specific dictionary; matched with lowest priority. */
  terms?: TermTrie;
  /** Restrict to these kinds. Defaults to all. */
  kinds?: ReadonlySet<PatternKind>;
}

/** All non-overlapping matches in `text`, sorted by position. */
export function detectAll(text: string, opts: DetectOptions = {}): Match[] {
  const enabled = (k: PatternKind) => !opts.kinds || opts.kinds.has(k);
  const candidates: Match[] = [];

  for (const d of DETECTORS) {
    if (!enabled(d.kind)) continue;
    for (const m of text.matchAll(d.pattern)) {
      const value = m[0];
      if (d.accept && !d.accept(value)) continue;
      candidates.push({ kind: d.kind, start: m.index!, end: m.index! + value.length, value });
    }
  }
  if (opts.terms && enabled("TERM")) candidates.push(...opts.terms.find(text));

  // Candidates are already in priority order; accept each unless it overlaps an accepted one.
  const accepted: Match[] = [];
  for (const c of candidates) {
    if (!accepted.some((a) => c.start < a.end && a.start < c.end)) accepted.push(c);
  }
  return accepted.sort((a, b) => a.start - b.start);
}
