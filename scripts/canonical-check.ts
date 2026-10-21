import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import canonicalizeImport from "canonicalize";

const SET_FIELDS = new Set([
  "ticket_ids",
  "customer_ids",
  "document_ids",
  "template_ids",
  "capabilities",
]);

type JsonValue = null | boolean | number | string | JsonValue[] | {[key: string]: JsonValue};
type Canonicalize = (value: JsonValue) => string | undefined;

const canonicalize = canonicalizeImport as unknown as Canonicalize;

function normalizeSets(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(normalizeSets);
  }
  if (value !== null && typeof value === "object") {
    const output: {[key: string]: JsonValue} = {};
    for (const [key, item] of Object.entries(value)) {
      if (SET_FIELDS.has(key) && Array.isArray(item)) {
        output[key] = item
          .map(normalizeSets)
          .sort((left, right) => {
            const leftCanonical = canonicalize(left);
            const rightCanonical = canonicalize(right);
            if (leftCanonical === undefined || rightCanonical === undefined) {
              throw new Error("canonicalize returned undefined");
            }
            return Buffer.compare(Buffer.from(leftCanonical), Buffer.from(rightCanonical));
          });
      } else {
        output[key] = normalizeSets(item);
      }
    }
    return output;
  }
  return value;
}

function sm3Hex(value: string): string {
  return createHash("sm3").update(Buffer.from(value, "utf8")).digest("hex");
}

const vectorPath = resolve("protocol/test-vectors/canonical-v1.json");
const vectors = JSON.parse(readFileSync(vectorPath, "utf8")) as {
  vectors: Array<{
    name: string;
    input: JsonValue;
    expected_canonical_utf8: string;
    expected_sm3_hex: string;
  }>;
};

for (const vector of vectors.vectors) {
  const canonical = canonicalize(normalizeSets(vector.input));
  if (canonical === undefined) {
    throw new Error(`${vector.name}: canonicalize returned undefined`);
  }
  if (canonical !== vector.expected_canonical_utf8) {
    throw new Error(
      `${vector.name}: canonical mismatch\nexpected=${vector.expected_canonical_utf8}\nactual=${canonical}`,
    );
  }
  const digest = sm3Hex(canonical);
  if (digest !== vector.expected_sm3_hex) {
    throw new Error(`${vector.name}: SM3 mismatch expected=${vector.expected_sm3_hex} actual=${digest}`);
  }
}

console.log(`verified ${vectors.vectors.length} canonical/SM3 vectors in TypeScript`);
