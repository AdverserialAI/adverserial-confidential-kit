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
const textEncoder = new TextEncoder();
export const canonicalize = (value) => {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    const object = value;
    return `{${Object.keys(object)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`)
        .join(',')}}`;
};
export const toBase64Url = (bytes) => {
    let binary = '';
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
};
export const fromBase64Url = (value) => {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};
// TypeScript's DOM declarations distinguish ArrayBuffer from ArrayBufferLike,
// while Uint8Array may be backed by either. WebCrypto needs a concrete copy.
export const asArrayBuffer = (bytes) => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return copy.buffer;
};
/** sha256:<base64url-no-padding> over the UTF-8 canonical form. */
export const sha256Digest = async (value) => {
    const digest = await crypto.subtle.digest('SHA-256', asArrayBuffer(textEncoder.encode(value)));
    return `sha256:${toBase64Url(new Uint8Array(digest))}`;
};
/** The receipt claim `evidence_sha256` for a parsed evidence object. */
export const evidenceDigest = async (evidence) => sha256Digest(canonicalize(evidence));
