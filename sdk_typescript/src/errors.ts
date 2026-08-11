export class EvidenceError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;

  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "EvidenceError";
    this.code = code;
    this.details = details;
  }
}

export function refuse(code: string, message: string, details: Record<string, unknown> = {}): never {
  throw new EvidenceError(code, message, details);
}
