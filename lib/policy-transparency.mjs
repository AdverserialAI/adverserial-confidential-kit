// Policy transparency: a verification policy is accepted only when the exact
// bytes that were served carry a Sigstore bundle that
//
//   1. chains to the pinned Sigstore trusted root (Fulcio CA, CT log, Rekor,
//      timestamp authority), with a verified transparency-log inclusion proof;
//   2. was issued to the one GitHub Actions workflow identity that is allowed
//      to publish policies (workflow file, branch, repository, trigger); and
//   3. is not older than the newest policy this installation has accepted.
//
// Verification is offline: nothing here talks to Fulcio, Rekor or a TUF
// mirror. The only network requests are the two GETs for the policy and its
// bundle, made by fetchSignedPolicy().
//
// Two modes. 'warn' (the default in this release) checks whatever is published
// and reports the result, but never blocks: an unsigned or unverifiable policy
// is still used, with a clear warning. 'enforce' refuses anything that is not
// signed, logged, from the publishing workflow and at least as new as the
// policy accepted before.
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { userHome } from './platform.mjs';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const BUNDLED_TRUSTED_ROOT = join(here, '..', 'resources', 'sigstore', 'trusted_root.json');
export const BUNDLE_SUFFIX = '.sigstore.json';
const MAX_POLICY_BYTES = 256 * 1024;
const MAX_BUNDLE_BYTES = 256 * 1024;
// published_at is written before review and signing, so it normally precedes
// the log time. It may never be later than the log time by more than this.
const PUBLISHED_AT_FUTURE_TOLERANCE_MS = 10 * 60 * 1000;

// The only identity allowed to publish a production policy. Every field is
// compared exactly. `repositoryId` and `ownerId` are GitHub's immutable
// numeric ids: they keep the pin valid across nothing and invalid across
// everything, including a deleted-and-recreated repository or organization of
// the same name.
export const PRODUCTION_SIGNER = Object.freeze({
  san: 'https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main',
  issuer: 'https://token.actions.githubusercontent.com',
  repository: 'https://github.com/AdverserialAI/confidential-policy',
  repositoryId: '1404762635',
  ownerId: '158311530',
  ref: 'refs/heads/main',
  trigger: 'push',
  runner: 'github-hosted'
});

// Nothing signed before this instant is accepted by this release, even on a
// machine with no local pin. Raise it in every release to the log time of the
// policy that was current when the release was cut.
export const POLICY_FLOOR = Object.freeze({ signedAt: '2026-11-19T14:41:23.000Z' });

// 'warn'    — this release: verify when a bundle is published, report
//             "signed", "unsigned" or "unverifiable", never block.
// 'enforce' — opt in now with ACK_POLICY_TRANSPARENCY=enforce or
//             `ack policy enforce`; a later release makes it the default.
export const DEFAULT_MODE = 'warn';
const MODE_FILE = 'policy-transparency-mode';

const FULCIO_OID = '1.3.6.1.4.1.57264.1.';
const EXTENSIONS = { issuer: 8, ref: 14, repository: 12, repositoryId: 15, ownerId: 17, trigger: 20, runner: 11, commit: 13, run: 21 };

export class PolicyTransparencyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PolicyTransparencyError';
    this.code = code;
  }
}
const refuse = (code, message) => { throw new PolicyTransparencyError(code, message); };

// The environment variable wins; otherwise the mode saved in the ACK home by
// `ack policy enforce|warn`; otherwise this release's default.
export function transparencyMode(env = process.env) {
  let value = env.ACK_POLICY_TRANSPARENCY;
  let source = 'ACK_POLICY_TRANSPARENCY';
  if (!value) {
    source = join(defaultStateDir(env), MODE_FILE);
    try { value = readFileSync(source, 'utf8').trim(); } catch { value = ''; }
  }
  value = (value || DEFAULT_MODE).toLowerCase();
  if (value !== 'warn' && value !== 'enforce') refuse('CONFIG', `${source} must be "warn" or "enforce".`);
  return value;
}

export async function saveTransparencyMode(mode, env = process.env) {
  if (mode !== 'warn' && mode !== 'enforce') refuse('CONFIG', 'The policy transparency mode is "warn" or "enforce".');
  const directory = defaultStateDir(env);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if (mode === DEFAULT_MODE) await rm(join(directory, MODE_FILE), { force: true });
  else await writeFile(join(directory, MODE_FILE), `${mode}\n`, { mode: 0o600 });
}

// @sigstore/verify 4 supports Node ^22.22.2 || ^24.15.0 || >=26. The kit still
// installs on older Node; there the signature cannot be checked.
export function nodeSupportsSigstore(version = process.versions.node) {
  const [major, minor, patch] = String(version).split('.').map(Number);
  if (major >= 26) return true;
  if (major === 24) return minor >= 15;
  if (major === 22) return minor > 22 || (minor === 22 && patch >= 2);
  return false;
}

let sigstore;
async function loadSigstore(nodeVersion = process.versions.node) {
  if (!nodeSupportsSigstore(nodeVersion)) {
    refuse('UNAVAILABLE', `policy signature not checked (Node too old): Node ${nodeVersion} cannot run the Sigstore verifier; it needs Node 22.22.2+, 24.15+ or 26+.`);
  }
  if (!sigstore) {
    try {
      const [bundle, core, specs, verify] = await Promise.all([
        import('@sigstore/bundle'), import('@sigstore/core'), import('@sigstore/protobuf-specs'), import('@sigstore/verify')
      ]);
      // Picked by name: these packages export some identically named things.
      sigstore = {
        bundleFromJSON: bundle.bundleFromJSON,
        RFC3161Timestamp: core.RFC3161Timestamp,
        X509Certificate: core.X509Certificate,
        TrustedRoot: specs.TrustedRoot,
        Verifier: verify.Verifier,
        toSignedEntity: verify.toSignedEntity,
        toTrustMaterial: verify.toTrustMaterial
      };
    } catch (error) {
      refuse('UNAVAILABLE', `policy signature not checked (the Sigstore verifier could not be loaded: ${error?.message || error}).`);
    }
  }
  return sigstore;
}

// The ACK home, where the policy pins live (same rule as appHome in ack.mjs).
export function defaultStateDir(env = process.env) {
  if (env.ACK_HOME) return resolve(env.ACK_HOME);
  return join(env.XDG_CONFIG_HOME || join(userHome(env), '.config'), 'adverserial');
}

export function loadTrustedRoot(path = BUNDLED_TRUSTED_ROOT) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function derUtf8(extension) {
  if (!extension) return undefined;
  // extnValue holds a DER UTF8String (Fulcio extensions .1.8 and later).
  const der = extension.valueObj.value;
  if (!der || der.length < 2 || der[0] !== 0x0c) return undefined;
  let offset = 2;
  let length = der[1];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 2) return undefined;
    length = 0;
    for (let i = 0; i < count; i += 1) length = (length << 8) | der[2 + i];
    offset = 2 + count;
  }
  if (offset + length !== der.length) return undefined;
  return der.subarray(offset).toString('utf8');
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Verify that `bundleJson` is a Sigstore bundle over exactly `policyBytes`,
 * issued to `signer`, and included in a transparency log of `trustedRoot`.
 * Rejects with PolicyTransparencyError; resolves to what was proven.
 */
export async function verifyPolicySignature({ policyBytes, bundleJson, signer = PRODUCTION_SIGNER, trustedRoot = loadTrustedRoot(), nodeVersion } = {}) {
  const { bundleFromJSON, RFC3161Timestamp, X509Certificate, TrustedRoot, Verifier, toSignedEntity, toTrustMaterial } = await loadSigstore(nodeVersion);
  if (!Buffer.isBuffer(policyBytes)) refuse('INPUT', 'Policy bytes are required.');
  for (const field of ['san', 'issuer', 'repository', 'ref', 'trigger']) {
    if (typeof signer?.[field] !== 'string' || !signer[field]) refuse('CONFIG', `Pinned signer is missing ${field}.`);
  }
  let bundle;
  try {
    bundle = bundleFromJSON(typeof bundleJson === 'string' ? JSON.parse(bundleJson) : bundleJson);
  } catch (error) {
    refuse('BUNDLE_FORMAT', `The policy signature bundle is not a valid Sigstore bundle (${error.message}).`);
  }
  if (bundle.content.$case !== 'messageSignature') refuse('BUNDLE_FORMAT', 'The policy bundle must sign the policy bytes directly.');
  const material = bundle.verificationMaterial;
  if (material.content.$case !== 'certificate' && material.content.$case !== 'x509CertificateChain') {
    refuse('BUNDLE_FORMAT', 'The policy bundle must carry a Fulcio signing certificate.');
  }
  if (!material.tlogEntries.length || material.tlogEntries.some((entry) => !entry.inclusionProof?.checkpoint?.envelope)) {
    // A signed entry timestamp alone is a promise to log. Require the proof.
    refuse('NOT_LOGGED', 'The policy bundle has no transparency-log inclusion proof.');
  }

  let identity;
  try {
    const verifier = new Verifier(toTrustMaterial(TrustedRoot.fromJSON(trustedRoot)), { tlogThreshold: 1, ctlogThreshold: 1, timestampThreshold: 1 });
    // @sigstore/verify treats a string identity as an unanchored pattern.
    // Anchor it here and compare it exactly again below.
    ({ identity } = verifier.verify(toSignedEntity(bundle, policyBytes), {
      subjectAlternativeName: new RegExp(`^${escapeRegExp(signer.san)}$`),
      extensions: { issuer: signer.issuer }
    }));
  } catch (error) {
    const code = error?.code === 'UNTRUSTED_SIGNER_ERROR' ? 'WRONG_SIGNER' : 'SIGNATURE';
    refuse(code, code === 'WRONG_SIGNER'
      ? 'The policy was not signed by the approved publishing workflow.'
      : `The policy signature did not verify (${error?.code || 'error'}: ${error?.message || error}).`);
  }
  if (identity?.subjectAlternativeName !== signer.san || identity?.extensions?.issuer !== signer.issuer) {
    refuse('WRONG_SIGNER', 'The policy was not signed by the approved publishing workflow.');
  }

  const rawCertificate = material.content.$case === 'certificate'
    ? material.content.certificate.rawBytes
    : material.content.x509CertificateChain.certificates[0].rawBytes;
  const certificate = X509Certificate.parse(rawCertificate);
  const claims = Object.fromEntries(Object.entries(EXTENSIONS).map(([name, arc]) => [name, derUtf8(certificate.extension(FULCIO_OID + arc))]));
  for (const field of ['issuer', 'repository', 'repositoryId', 'ownerId', 'ref', 'trigger', 'runner']) {
    if (signer[field] !== undefined && claims[field] !== signer[field]) {
      refuse('WRONG_SIGNER', `The policy signing certificate has an unexpected ${field}.`);
    }
  }

  // Times that the verifier above has checked: the Rekor entry time is covered
  // by the signed entry timestamp, the RFC 3161 time by the timestamp
  // authority. The signing certificate was valid at each of them.
  const times = [];
  for (const entry of material.tlogEntries) if (entry.inclusionPromise) times.push(Number(entry.integratedTime) * 1000);
  for (const stamp of material.timestampVerificationData?.rfc3161Timestamps ?? []) times.push(RFC3161Timestamp.parse(stamp.signedTimestamp).signingTime.getTime());
  if (!times.length || times.some((time) => !Number.isFinite(time))) refuse('SIGNATURE', 'The policy bundle has no verified signing time.');

  return {
    sha256: createHash('sha256').update(policyBytes).digest('hex'),
    signedAt: new Date(Math.min(...times)).toISOString(),
    log: material.tlogEntries.map((entry) => ({
      logId: Buffer.from(entry.logId.keyId).toString('base64'),
      logIndex: String(entry.logIndex),
      kind: `${entry.kindVersion.kind}/${entry.kindVersion.version}`
    })),
    signer: { san: identity.subjectAlternativeName, ...claims }
  };
}

/**
 * Rollback protection. Order is the verified log time, which the signer cannot
 * choose: replaying an older, validly signed policy presents an older time.
 * Returns the pin to store once the policy has been accepted.
 */
export function checkNotRolledBack({ policy, verification, pin = null, floor = POLICY_FLOOR }) {
  const signedAt = Date.parse(verification.signedAt);
  const publishedAt = Date.parse(policy?.published_at ?? '');
  if (!Number.isFinite(publishedAt)) refuse('POLICY', 'The signed policy has no published_at time.');
  if (publishedAt > signedAt + PUBLISHED_AT_FUTURE_TOLERANCE_MS) refuse('POLICY', 'The policy claims to be published after it was signed.');
  if (floor?.signedAt && signedAt < Date.parse(floor.signedAt)) {
    refuse('ROLLBACK', 'The policy is older than the minimum this release accepts.');
  }
  if (pin?.signedAt) {
    const pinned = Date.parse(pin.signedAt);
    if (signedAt < pinned) refuse('ROLLBACK', `The policy was signed ${verification.signedAt}, before the policy already accepted here (${pin.signedAt}).`);
    if (signedAt === pinned && pin.sha256 !== verification.sha256) refuse('ROLLBACK', 'A different policy carries the same signing time as the accepted one.');
    if (signedAt > pinned && pin.publishedAt && publishedAt < Date.parse(pin.publishedAt)) {
      refuse('ROLLBACK', 'A newer signature covers a policy with an older published_at than the accepted one.');
    }
  }
  return {
    signed: true,
    sha256: verification.sha256,
    signedAt: verification.signedAt,
    publishedAt: policy.published_at,
    logIndex: verification.log[0]?.logIndex,
    logId: verification.log[0]?.logId
  };
}

const pinFile = (stateDir) => join(stateDir, 'policy-pins.json');

export async function readPins(stateDir) {
  if (!stateDir) return {};
  let text;
  try { text = await readFile(pinFile(stateDir), 'utf8'); } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
  // A pin file that cannot be read is not the same as no pin: do not silently
  // fall back to accepting anything.
  try {
    const pins = JSON.parse(text);
    if (pins && typeof pins === 'object' && !Array.isArray(pins)) return pins;
  } catch { /* fall through */ }
  refuse('PIN', `The policy pin file is damaged: ${pinFile(stateDir)}. Remove it only if you accept re-pinning the published policy.`);
}

export async function writePins(stateDir, pins) {
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const temporary = `${pinFile(stateDir)}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, pinFile(stateDir));
}

async function fetchBytes(url, fetchImpl, limit, what, { optional = false } = {}) {
  let response;
  try {
    response = await fetchImpl(url, { headers: { accept: 'application/json' }, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10_000) });
  } catch (error) {
    if (optional) return { missing: true, reason: `unreachable (${error?.message || error})` };
    refuse('FETCH', `Could not fetch the ${what}.`);
  }
  if (!response.ok) {
    if (optional && response.status === 404) return { missing: true, reason: 'not published (404)' };
    refuse('FETCH', `Could not fetch the ${what} (${response.status}).`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > limit) refuse('FETCH', `The ${what} is larger than expected.`);
  return { bytes };
}

/**
 * Fetch `url` and `url + ".sigstore.json"`, verify, apply rollback protection
 * and (when `stateDir` is given) advance the local pin.
 *
 * Returns { policy, bytes, status, reason, verification, mode, warnings }:
 *   status 'signed'        the bundle verified and the policy is not a rollback
 *          'unsigned'      no bundle is published               (warn mode only)
 *          'unverifiable'  a bundle exists but was not accepted (warn mode only)
 * In enforce mode anything but 'signed' rejects with PolicyTransparencyError.
 * `policy` is parsed from the fetched bytes; no other copy is ever used.
 */
export async function fetchSignedPolicy({
  url, fetchImpl = fetch, stateDir, mode = transparencyMode(), signer = PRODUCTION_SIGNER,
  trustedRoot, floor = POLICY_FLOOR, pinKey = url, nodeVersion,
  // Tests verify a real signature over a file that is not a policy document.
  decode = (bytes) => JSON.parse(bytes.toString('utf8'))
} = {}) {
  if (mode !== 'warn' && mode !== 'enforce') refuse('CONFIG', 'Unknown policy transparency mode.');
  const enforce = mode === 'enforce';
  const warnings = [];
  let pins = {};
  let pinsUsable = true;
  try { pins = await readPins(stateDir); } catch (error) {
    if (enforce) throw error;
    pinsUsable = false;
    warnings.push(error.message);
  }
  const pin = pins[pinKey] ?? null;
  let policyBytes;
  let policy;
  let verification = null;
  let status = 'unsigned';
  let reason = '';
  // The policy and its bundle are two requests. A deploy between them shows up
  // as a signature over other bytes; one retry of both is enough to pass it.
  for (let attempt = 0; ; attempt += 1) {
    verification = null;
    ({ bytes: policyBytes } = await fetchBytes(url, fetchImpl, MAX_POLICY_BYTES, 'published policy'));
    try { policy = decode(policyBytes); } catch { refuse('POLICY', 'The published policy is not valid JSON.'); }
    const bundle = await fetchBytes(url + BUNDLE_SUFFIX, fetchImpl, MAX_BUNDLE_BYTES, 'policy signature bundle', { optional: true });
    if (bundle.missing) {
      reason = bundle.reason;
      if (enforce) refuse('UNSIGNED', `The published policy has no transparency signature (${reason}); it is refused because policy transparency is enforced.`);
      warnings.push(`The published policy has no transparency signature (${reason}). It is used on HTTPS trust alone; a later ACK release will refuse it.`);
      break;
    }
    try {
      verification = await verifyPolicySignature({ policyBytes, bundleJson: bundle.bytes.toString('utf8'), signer, trustedRoot: trustedRoot ?? loadTrustedRoot(), nodeVersion });
      const next = checkNotRolledBack({ policy, verification, pin, floor });
      if (stateDir && pinsUsable && (pin?.sha256 !== next.sha256 || pin?.signedAt !== next.signedAt)) await writePins(stateDir, { ...pins, [pinKey]: next });
      status = 'signed';
      break;
    } catch (error) {
      if (!(error instanceof PolicyTransparencyError)) throw error;
      if (attempt === 0 && error.code === 'SIGNATURE') continue;
      if (enforce) throw error;
      status = 'unverifiable';
      reason = error.message;
      warnings.push(error.code === 'UNAVAILABLE'
        ? `The ${error.message} The policy is used on HTTPS trust alone.`
        : `The published policy's transparency signature was NOT accepted: ${error.message} The policy is still used because policy transparency is in warn mode; set ACK_POLICY_TRANSPARENCY=enforce to refuse it.`);
      break;
    }
  }
  return { policy, bytes: policyBytes, status, reason, verification, mode, warnings };
}

/** One line for people: what was established about the policy just fetched. */
export function describePolicyStatus(result) {
  if (result.status === 'signed') {
    const { verification } = result;
    return `signed by ${verification.signer.san}; Rekor log index ${verification.log[0]?.logIndex}; logged ${verification.signedAt}; sha256:${verification.sha256}`;
  }
  if (result.status === 'unsigned') return `unsigned (${result.reason}); used on HTTPS trust alone [mode: ${result.mode}]`;
  return `unverifiable: ${result.reason} [mode: ${result.mode}]`;
}
