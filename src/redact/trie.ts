import type { Match } from "./types.js";

interface Node {
  children: Map<string, Node>;
  /** Set when a configured term ends at this node. */
  terminal: boolean;
}

const newNode = (): Node => ({ children: new Map(), terminal: false });
function isWordChar(ch: string | undefined): boolean {
  if (ch === undefined) return false;
  const c = ch.charCodeAt(0);
  // ASCII fast path; this runs once per character scanned.
  if (c < 128) return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
  return /[\p{L}\p{N}]/u.test(ch);
}

/**
 * Case-insensitive dictionary matcher for customer-specific sensitive terms
 * (account names, project codenames, people). Runs fully on-box: a scan is
 * O(text length × longest term) with no regex compilation per term.
 */
export class TermTrie {
  private readonly root = newNode();
  private count = 0;

  constructor(terms: Iterable<string> = []) {
    for (const t of terms) this.add(t);
  }

  get size(): number {
    return this.count;
  }

  add(term: string): void {
    const normalized = term.trim().toLowerCase();
    if (!normalized) return;
    let node = this.root;
    for (const ch of normalized) {
      let next = node.children.get(ch);
      if (!next) {
        next = newNode();
        node.children.set(ch, next);
      }
      node = next;
    }
    if (!node.terminal) this.count++;
    node.terminal = true;
  }

  /** Longest whole-word matches, left to right, non-overlapping. */
  find(text: string): Match[] {
    const out: Match[] = [];
    const lower = text.toLowerCase();
    let i = 0;
    while (i < lower.length) {
      if (isWordChar(lower[i - 1])) {
        i++;
        continue;
      }
      let node: Node | undefined = this.root;
      let end = -1;
      for (let j = i; j < lower.length && node; j++) {
        node = node.children.get(lower[j]!);
        if (node?.terminal && !isWordChar(lower[j + 1])) end = j + 1;
      }
      if (end > 0) {
        out.push({ kind: "TERM", start: i, end, value: text.slice(i, end) });
        i = end;
      } else {
        i++;
      }
    }
    return out;
  }
}
