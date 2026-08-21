import { refuse } from "./errors.ts";
import type { JsonValue } from "./json.ts";

/**
 * The publication states ES-035's table distinguishes.
 *
 * They fail for different reasons and are kept apart so the diagnostic says
 * which mistake was made. A version *absent* from a registry was never
 * published and there are no rules to apply. A version listed as *reserved*
 * has been allocated but its rules are not written, and ES-035 requires
 * refusing it rather than guessing at them.
 */
export type VersionStatus = "published" | "reserved";

/** ES-035. Adding a row is a specification change requiring a vector. */
export const SCHEMA_VERSION_REGISTRY: Readonly<Record<string, VersionStatus>> = Object.freeze({
  "1.0.0": "published",
  // ES-031 changes the constitutive-record enumeration at this version. No
  // implementation supports it and no vector carries it.
  "2.0.0": "reserved",
});

/** CM-025. Adding a row is a material change under CM-024. */
export const METHODOLOGY_VERSION_REGISTRY: Readonly<Record<string, VersionStatus>> = Object.freeze({
  "1.0.0": "published",
});

/** The versions of a registry a verifier is obliged to support. */
export function publishedVersions(registry: Readonly<Record<string, VersionStatus>>): string[] {
  return Object.entries(registry)
    .filter(([, status]) => status === "published")
    .map(([version]) => version)
    .sort();
}

/** ES-035: refuse a `schema_version` outside the published set. */
export function requirePublishedSchemaVersion(value: JsonValue | undefined): string {
  return requirePublished(value, SCHEMA_VERSION_REGISTRY, "schema_version", "schema.version_unsupported");
}

/** CM-025: refuse a `methodology_version` outside the published set. */
export function requirePublishedMethodologyVersion(value: JsonValue | undefined): string {
  return requirePublished(value, METHODOLOGY_VERSION_REGISTRY, "methodology_version", "methodology.version_unsupported");
}

function requirePublished(value: JsonValue | undefined, registry: Readonly<Record<string, VersionStatus>>, label: string, code: string): string {
  if (typeof value !== "string") refuse(code, `${label} is required and must be a string`);
  const status = registry[value];
  if (status === undefined) {
    refuse(code, `${label} ${value} is not published; published versions are ${publishedVersions(registry).join(", ")}`);
  }
  if (status !== "published") {
    refuse(code, `${label} ${value} is reserved and not yet published: a verifier must refuse rather than guess at rules that are not written`);
  }
  return value;
}
