/**
 * Adverserial Encrypted HTTP Body Protocol (EHBP) v1.
 *
 * RFC 9180 base-mode HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM. The server receiver key comes only from verified, quote-bound
 * evidence; this module never accepts an unverified key from an API response.
 */
import { fromBase64Url, toBase64Url } from './canonjson.js';
export const EHBP_VERSION = 'adverserial-ehbp-v1';
export const EHBP_CONTENT_TYPE = 'application/adverserial-ehbp+json';
export const EHBP_KEM = 'DHKEM(X25519,HKDF-SHA256)';
export const EHBP_KDF = 'HKDF-SHA256';
export const EHBP_AEAD = 'AES-256-GCM';
const kemID = 0x0020;
const kdfID = 0x0001;
const aeadID = 0x0002;
const encoder = new TextEncoder();
const concat = (...parts) => {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const out = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};
const u16 = (value) => new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
const kemSuite = concat(encoder.encode('KEM'), u16(kemID));
const hpkeSuite = concat(encoder.encode('HPKE'), u16(kemID), u16(kdfID), u16(aeadID));
const asBuffer = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
const hmac = async (keyBytes, data) => {
    const key = await crypto.subtle.importKey('raw', asBuffer(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, asBuffer(data)));
};
const extract = async (salt, ikm) => hmac(salt.length ? salt : new Uint8Array(32), ikm);
const expand = async (prk, info, length) => {
    if (length > 255 * 32)
        throw new Error('EHBP HKDF output is too long.');
    const chunks = [];
    let previous = new Uint8Array();
    for (let counter = 1; chunks.reduce((total, part) => total + part.length, 0) < length; counter += 1) {
        previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])));
        chunks.push(previous);
    }
    return concat(...chunks).slice(0, length);
};
const labeledExtract = (salt, label, ikm, suite) => extract(salt, concat(encoder.encode('HPKE-v1'), suite, encoder.encode(label), ikm));
const labeledExpand = (prk, label, info, length, suite) => expand(prk, concat(u16(length), encoder.encode('HPKE-v1'), suite, encoder.encode(label), info), length);
const sharedSecret = async (dh, enc, recipient) => {
    const eaePrk = await labeledExtract(new Uint8Array(), 'eae_prk', dh, kemSuite);
    return labeledExpand(eaePrk, 'shared_secret', concat(enc, recipient), 32, kemSuite);
};
const keyAndNonce = async (shared, info) => {
    const pskIDHash = await labeledExtract(new Uint8Array(), 'psk_id_hash', new Uint8Array(), hpkeSuite);
    const infoHash = await labeledExtract(new Uint8Array(), 'info_hash', info, hpkeSuite);
    const context = concat(new Uint8Array([0]), pskIDHash, infoHash);
    const secret = await labeledExtract(shared, 'secret', new Uint8Array(), hpkeSuite);
    return { key: await labeledExpand(secret, 'key', context, 32, hpkeSuite), nonce: await labeledExpand(secret, 'base_nonce', context, 12, hpkeSuite) };
};
const importX25519Public = (raw) => {
    if (raw.length !== 32)
        throw new Error('EHBP X25519 public key must be 32 bytes.');
    return crypto.subtle.importKey('raw', asBuffer(raw), { name: 'X25519' }, false, []);
};
const generateX25519 = async () => crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
const derive = async (privateKey, publicKey) => new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
const rawPublic = async (key) => new Uint8Array(await crypto.subtle.exportKey('raw', key));
export const requestInfo = () => encoder.encode(`${EHBP_VERSION}/request`);
export const responseInfo = () => encoder.encode(`${EHBP_VERSION}/response`);
export const ehbpAAD = (method, path, nonce) => encoder.encode(`${EHBP_VERSION}\n${method}\n${path}\n${nonce}`);
export const sealEHBP = async (recipientRaw, plaintext, info, aad) => {
    const recipient = await importX25519Public(recipientRaw);
    const ephemeral = await generateX25519();
    const enc = await rawPublic(ephemeral.publicKey);
    const shared = await sharedSecret(await derive(ephemeral.privateKey, recipient), enc, recipientRaw);
    const { key, nonce } = await keyAndNonce(shared, info);
    const aeadKey = await crypto.subtle.importKey('raw', asBuffer(key), { name: 'AES-GCM' }, false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: asBuffer(nonce), additionalData: asBuffer(aad), tagLength: 128 }, aeadKey, asBuffer(plaintext)));
    return { version: EHBP_VERSION, kem: EHBP_KEM, kdf: EHBP_KDF, aead: EHBP_AEAD, enc: toBase64Url(enc), ciphertext: toBase64Url(ciphertext) };
};
export const openEHBPWithKeyPair = async (receiver, envelope, info, aad) => {
    if (envelope.version !== EHBP_VERSION || envelope.kem !== EHBP_KEM || envelope.kdf !== EHBP_KDF || envelope.aead !== EHBP_AEAD)
        throw new Error('Unsupported EHBP suite.');
    const enc = fromBase64Url(envelope.enc);
    const ciphertext = fromBase64Url(envelope.ciphertext);
    if (enc.length !== 32 || ciphertext.length < 16)
        throw new Error('Invalid EHBP envelope.');
    const sender = await importX25519Public(enc);
    const recipientRaw = await rawPublic(receiver.publicKey);
    const shared = await sharedSecret(await derive(receiver.privateKey, sender), enc, recipientRaw);
    const { key, nonce } = await keyAndNonce(shared, info);
    const aeadKey = await crypto.subtle.importKey('raw', asBuffer(key), { name: 'AES-GCM' }, false, ['decrypt']);
    try {
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: asBuffer(nonce), additionalData: asBuffer(aad), tagLength: 128 }, aeadKey, asBuffer(ciphertext)));
    }
    catch {
        throw new Error('EHBP authentication failed.');
    }
};
// X25519 WebCrypto APIs do not derive the public key from an opaque private
// CryptoKey. Keeping the generated pair is therefore required for response
// decryption and prevents callers from accidentally using an unrelated key.
export const openEHBP = openEHBPWithKeyPair;
export const generateEHBPReceiver = generateX25519;
export const exportEHBPReceiverPublic = rawPublic;
export const parseEHBPEnvelope = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Invalid EHBP envelope.');
    const raw = value;
    const keys = ['version', 'kem', 'kdf', 'aead', 'enc', 'ciphertext'];
    if (Object.keys(raw).length !== keys.length || keys.some((key) => typeof raw[key] !== 'string'))
        throw new Error('Invalid EHBP envelope.');
    const envelope = raw;
    if (envelope.version !== EHBP_VERSION || envelope.kem !== EHBP_KEM || envelope.kdf !== EHBP_KDF || envelope.aead !== EHBP_AEAD)
        throw new Error('Unsupported EHBP suite.');
    return envelope;
};
export const attestedEHBPReceiver = async (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Attestation evidence has no EHBP metadata.');
    const meta = value;
    if (meta.version !== EHBP_VERSION || meta.kem !== EHBP_KEM || meta.kdf !== EHBP_KDF || meta.aead !== EHBP_AEAD || typeof meta.public_key !== 'string' || typeof meta.public_key_sha256 !== 'string')
        throw new Error('Attestation EHBP metadata is invalid.');
    const raw = fromBase64Url(meta.public_key);
    if (raw.length !== 32)
        throw new Error('Attestation EHBP receiver key has an invalid length.');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', asBuffer(raw)));
    if (`sha256:${toBase64Url(digest)}` !== meta.public_key_sha256)
        throw new Error('Attestation EHBP receiver key digest does not match.');
    return raw;
};
