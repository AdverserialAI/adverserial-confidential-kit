import { formatVerdict } from '../opencode/dist/plugins/shared/src/format.js';

export function verificationDeadline(verdict, now = Date.now()) {
  const verifiedAt = verdict?.verifiedAt;
  const expires = verdict?.proof?.expiresEpoch * 1000;
  if (verdict?.status !== 'verified' || verdict.trust !== 'pinned' || verdict.proof?.devMode !== false ||
      !Number.isFinite(verifiedAt) || verifiedAt > now + 5000 || !Number.isFinite(verdict?.proof?.expiresEpoch) || !Number.isFinite(expires)) return 0;
  const deadline = Math.min(expires, verifiedAt + 300_000);
  return deadline > now ? deadline : 0;
}

export function parseVerifierResult(code, stdout, stderr = '', now = Date.now()) {
  let verdict;
  try { verdict = JSON.parse(stdout); } catch {
    return { ok: false, output: stderr.trim() || 'Attestation verifier returned no valid JSON verdict.', verdict: null };
  }
  const ok = code === 0 && Boolean(verificationDeadline(verdict, now));
  let output;
  try { output = formatVerdict(verdict, now); } catch { output = 'Attestation verifier returned an incomplete verdict.'; }
  if (verdict.status === 'verified' && !ok) output = 'ADVERSERIAL ATTESTATION: NOT VERIFIED (failed, stale, unpinned, or incomplete verdict)';
  return { ok, output, verdict };
}

export function createAttestationStatus(render, { now = Date.now, schedule = setTimeout, cancel = clearTimeout } = {}) {
  let verdict = null, invalidated = false, timer;
  const clear = () => { if (timer !== undefined) cancel(timer); timer = undefined; };
  const refresh = () => {
    clear();
    const deadline = invalidated ? 0 : verificationDeadline(verdict, now());
    if (deadline) {
      render('success', '✓ Adverserial attestation verified');
      timer = schedule(refresh, deadline - now()); timer?.unref?.();
    } else if (!invalidated && verdict?.status === 'verified' && verdict.trust === 'pinned' && !verdict.proof?.devMode) {
      render('warning', '⚠ Adverserial attestation expired — run /adverserial-verify');
    } else {
      render('error', '✕ Adverserial attestation needs attention — run /adverserial-verify');
    }
  };
  return {
    update(result) { verdict = result.verdict; invalidated = !result.ok; refresh(); },
    invalidate() { invalidated = true; refresh(); },
    refresh,
    dispose: clear,
  };
}

export function installAttestationStatus(pi, initial) {
  let context;
  const status = createAttestationStatus((tone, label) => {
    if (context) context.ui.setStatus('adverserial-attestation', context.ui.theme.fg(tone, label));
  });
  const update = (result, ctx) => { if (ctx) context = ctx; status.update(result); };
  const inspect = (message, ctx) => {
    if (ctx) context = ctx;
    if (message?.role !== 'assistant' || (context?.model?.provider && context.model.provider !== 'adverserial-confidential')) return;
    if (/confidential endpoint verification failed|independent hardware verifier|confidential.*receipt.*(?:failed|invalid|missing)/i.test(message.errorMessage || '')) status.invalidate();
  };
  pi.on('session_start', async (_event, ctx) => { update(initial, ctx); });
  pi.on('before_agent_start', async (_event, ctx) => { context = ctx; status.refresh(); });
  pi.on('message_end', async (event, ctx) => { inspect(event.message, ctx); });
  pi.on('agent_end', async (event, ctx) => { inspect((event.messages || []).filter(m => m.role === 'assistant').at(-1), ctx); });
  pi.on('session_shutdown', async () => { status.dispose(); context = null; });
  return { update };
}
