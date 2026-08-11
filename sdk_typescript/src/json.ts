import { EvidenceError, refuse } from "./errors.ts";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

const MAX_SAFE_INTEGER = 9_007_199_254_740_991n;
export const MAX_JSON_NESTING_DEPTH = 512;

/** Parse the source tokens required by ES-002a without losing their spelling. */
export function parseCanonicalJson(source: string): JsonValue {
  return new JsonTokenParser(source).parse();
}

export function canonicalizeJson(source: string): Uint8Array {
  return canonicalize(parseCanonicalJson(source));
}

/** RFC 8785 serialization over the ES subset (integers only). */
export function canonicalize(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalStringify(value));
}

export function canonicalStringify(value: JsonValue): string {
  return stringify(value, 0);
}

function stringify(value: JsonValue, depth: number): string {
  if (depth > MAX_JSON_NESTING_DEPTH) {
    refuse("canonicalization.nesting_too_deep", `JSON nesting exceeds ${MAX_JSON_NESTING_DEPTH}`);
  }
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quoteString(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      refuse("canonicalization.float_forbidden", "signed JSON numbers must be integers");
    }
    if (!Number.isSafeInteger(value)) {
      refuse("canonicalization.integer_out_of_range", "integer exceeds the interoperable range");
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringify(item, depth + 1)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.keys(value)
      .sort(compareUtf16)
      .map((key) => `${quoteString(key)}:${stringify(value[key]!, depth + 1)}`);
    return `{${entries.join(",")}}`;
  }
  return refuse("canonicalization.unsupported_value", "value is not JSON");
}

function compareUtf16(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function quoteString(value: string): string {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        refuse("canonicalization.lone_surrogate", "unpaired high surrogate in string");
      }
      output += value[index]! + value[index + 1]!;
      index += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      refuse("canonicalization.lone_surrogate", "unpaired low surrogate in string");
    }
    switch (code) {
      case 0x08: output += "\\b"; break;
      case 0x09: output += "\\t"; break;
      case 0x0a: output += "\\n"; break;
      case 0x0c: output += "\\f"; break;
      case 0x0d: output += "\\r"; break;
      case 0x22: output += '\\"'; break;
      case 0x5c: output += "\\\\"; break;
      default:
        output += code <= 0x1f ? `\\u${code.toString(16).padStart(4, "0")}` : value[index]!;
    }
  }
  return `${output}"`;
}

class JsonTokenParser {
  private position = 0;
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.position !== this.source.length) this.invalid("trailing content");
    return value;
  }

  private parseValue(depth: number): JsonValue {
    if (depth > MAX_JSON_NESTING_DEPTH) {
      refuse("canonicalization.nesting_too_deep", `JSON nesting exceeds ${MAX_JSON_NESTING_DEPTH}`);
    }
    this.skipWhitespace();
    const char = this.source[this.position];
    if (char === '"') return this.parseString();
    if (char === "{") return this.parseObject(depth);
    if (char === "[") return this.parseArray(depth);
    if (char === "t") return this.literal("true", true);
    if (char === "f") return this.literal("false", false);
    if (char === "n") {
      if (this.source.startsWith("null", this.position)) return this.literal("null", null);
      if (this.source.startsWith("nan", this.position)) this.floatForbidden();
    }
    if (char === "N" || char === "I" || this.source.startsWith("-Infinity", this.position)) {
      this.floatForbidden();
    }
    if (char === "-" || (char !== undefined && char >= "0" && char <= "9")) {
      return this.parseNumber();
    }
    return this.invalid("expected a JSON value");
  }

  private parseObject(depth: number): JsonObject {
    this.position += 1;
    const result: JsonObject = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.consume("}")) return result;
    while (true) {
      if (this.source[this.position] !== '"') this.invalid("object key must be a string");
      const key = this.parseString();
      if (seen.has(key)) refuse("canonicalization.duplicate_key", `duplicate object key ${key}`);
      seen.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.invalid("expected ':' after object key");
      const parsed = this.parseValue(depth + 1);
      Object.defineProperty(result, key, {
        value: parsed,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      this.skipWhitespace();
      if (this.consume("}")) return result;
      if (!this.consume(",")) this.invalid("expected ',' or '}' in object");
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.position += 1;
    const result: JsonValue[] = [];
    this.skipWhitespace();
    if (this.consume("]")) return result;
    while (true) {
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      if (!this.consume(",")) this.invalid("expected ',' or ']' in array");
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    this.position += 1;
    let output = "";
    while (this.position < this.source.length) {
      const code = this.source.charCodeAt(this.position++);
      if (code === 0x22) return output;
      if (code <= 0x1f) this.invalid("unescaped control character in string");
      if (code === 0x5c) {
        const escape = this.source[this.position++];
        const simple: Record<string, string> = {
          '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
        };
        if (escape !== undefined && Object.hasOwn(simple, escape)) {
          output += simple[escape];
          continue;
        }
        if (escape !== "u") this.invalid("invalid string escape");
        const first = this.readHexCodeUnit();
        if (first >= 0xd800 && first <= 0xdbff) {
          if (this.source.slice(this.position, this.position + 2) !== "\\u") {
            refuse("canonicalization.lone_surrogate", "unpaired escaped high surrogate");
          }
          this.position += 2;
          const second = this.readHexCodeUnit();
          if (!(second >= 0xdc00 && second <= 0xdfff)) {
            refuse("canonicalization.lone_surrogate", "unpaired escaped high surrogate");
          }
          output += String.fromCharCode(first, second);
        } else if (first >= 0xdc00 && first <= 0xdfff) {
          refuse("canonicalization.lone_surrogate", "unpaired escaped low surrogate");
        } else {
          output += String.fromCharCode(first);
        }
        continue;
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = this.source.charCodeAt(this.position);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          refuse("canonicalization.lone_surrogate", "unpaired raw high surrogate");
        }
        output += String.fromCharCode(code, next);
        this.position += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        refuse("canonicalization.lone_surrogate", "unpaired raw low surrogate");
      } else {
        output += String.fromCharCode(code);
      }
    }
    return this.invalid("unterminated string");
  }

  private readHexCodeUnit(): number {
    const token = this.source.slice(this.position, this.position + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(token)) this.invalid("invalid unicode escape");
    this.position += 4;
    return Number.parseInt(token, 16);
  }

  private parseNumber(): number {
    const start = this.position;
    if (this.consume("-")) {
      if (this.source.startsWith("Infinity", this.position)) this.floatForbidden();
    }
    if (this.consume("0")) {
      if (this.isDigit(this.source[this.position])) this.invalid("leading zero in number");
    } else {
      if (!this.isDigitOneToNine(this.source[this.position])) this.invalid("invalid number");
      while (this.isDigit(this.source[this.position])) this.position += 1;
    }
    if (this.source[this.position] === "." || this.source[this.position] === "e" || this.source[this.position] === "E") {
      this.consumeNumberTail();
      this.floatForbidden();
    }
    const token = this.source.slice(start, this.position);
    let integer: bigint;
    try {
      integer = BigInt(token);
    } catch {
      return this.invalid("invalid integer token");
    }
    if (integer < -MAX_SAFE_INTEGER || integer > MAX_SAFE_INTEGER) {
      refuse("canonicalization.integer_out_of_range", `integer ${token} is outside the ES range`);
    }
    return Number(integer);
  }

  private consumeNumberTail(): void {
    while (this.position < this.source.length && /[0-9eE+.-]/.test(this.source[this.position]!)) {
      this.position += 1;
    }
  }

  private literal<T extends JsonPrimitive>(token: string, value: T): T {
    if (!this.source.startsWith(token, this.position)) this.invalid(`invalid literal ${token}`);
    this.position += token.length;
    return value;
  }

  private skipWhitespace(): void {
    while (/\s/.test(this.source[this.position] ?? "") && " \t\r\n".includes(this.source[this.position]!)) {
      this.position += 1;
    }
  }

  private consume(token: string): boolean {
    if (!this.source.startsWith(token, this.position)) return false;
    this.position += token.length;
    return true;
  }

  private isDigit(char: string | undefined): boolean {
    return char !== undefined && char >= "0" && char <= "9";
  }

  private isDigitOneToNine(char: string | undefined): boolean {
    return char !== undefined && char >= "1" && char <= "9";
  }

  private floatForbidden(): never {
    return refuse("canonicalization.float_forbidden", "fraction, exponent, NaN, and Infinity tokens are forbidden");
  }

  private invalid(message: string): never {
    throw new EvidenceError("canonicalization.invalid_json", `${message} at offset ${this.position}`);
  }
}
