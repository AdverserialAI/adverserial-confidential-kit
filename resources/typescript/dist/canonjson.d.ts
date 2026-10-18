/**
 * Canonical JSON encoding, byte-identical to canonicalize() in the reference
 * client (adverserial-webui src/lib/confidential/verification.ts) and to the
 * attest-proxy's Go internal/canonjson package:
 *
 *   - object keys sorted recursively (JS sort: UTF-16 code-unit order),
 *   - no whitespace,
 *   - JSON.stringify string semantics: only '"', '\' and control chars < 0x20
 *     escaped; non-ASCII, DEL, U+2028/U+2029 and '<', '>', '&' raw,
 *   - numbers via JSON.stringify semantics (the protocol carries integers).
 */
export type JsonRecord = Record<string, unknown>;
export declare const canonicalize: (value: unknown) => string;
export declare const toBase64Url: (bytes: Uint8Array) => string;
export declare const fromBase64Url: (value: string) => Uint8Array;
export declare const asArrayBuffer: (bytes: Uint8Array) => ArrayBuffer;
/** sha256:<base64url-no-padding> over the UTF-8 canonical form. */
export declare const sha256Digest: (value: string) => Promise<string>;
/** The receipt claim `evidence_sha256` for a parsed evidence object. */
export declare const evidenceDigest: (evidence: JsonRecord) => Promise<string>;
