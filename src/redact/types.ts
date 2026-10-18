/** Categories the gateway can redact. Pattern kinds come from text; field kinds come from JSON keys. */
export const PATTERN_KINDS = ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS", "SECRET", "TERM"] as const;
export const FIELD_KINDS = ["PERSON_NAME", "ADDRESS", "DATE_OF_BIRTH"] as const;

export type PatternKind = (typeof PATTERN_KINDS)[number];
export type FieldKind = (typeof FIELD_KINDS)[number];
export type PiiKind = PatternKind | FieldKind;

/** A span found in text. `value` never leaves the engine. */
export interface Match {
  kind: PatternKind;
  start: number;
  end: number;
  value: string;
}

/** What the outside world (audit log, View, model) learns about a redaction: the kind and the token, never the value. */
export interface Finding {
  kind: PiiKind;
  token: string;
  /** JSON path for structured content, e.g. `customers[0].email`. */
  path?: string;
}
