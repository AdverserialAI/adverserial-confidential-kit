import { asArrayBuffer } from './canonjson.js';
const hex = (a) => Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
const bytes = (s) => {
    if (typeof s !== 'string' || s.length % 2 || !/^[a-f0-9]*$/i.test(s))
        throw new Error('Invalid hex in TDX runtime event.');
    return Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
};
const concat = (...arrays) => { const a = new Uint8Array(arrays.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of arrays) {
    a.set(x, i);
    i += x.length;
} return a; };
const sha384 = async (a) => new Uint8Array(await crypto.subtle.digest('SHA-384', asArrayBuffer(a)));
/** dstack v0.5.x event-log V1. See cc-eventlog/src/runtime_events.rs at v0.5.9. */
export const verifyTDXWorkload = async (report, eventLog, policy) => {
    if ((report.tdAttributes[0] & 1) !== 0)
        throw new Error('Debug-enabled TDX workloads are not accepted.');
    const events = typeof eventLog === 'string' ? JSON.parse(eventLog) : eventLog;
    if (!Array.isArray(events) || !events.length || events.length > 4096)
        throw new Error('Invalid TDX event log.');
    const lane = events.filter(e => e && e.imr === 3);
    if (!lane.length)
        throw new Error('The TDX event log has no RTMR3 events.');
    let mr = new Uint8Array(48);
    for (const e of lane) {
        if (e.event_type !== 0x08000001 || typeof e.event !== 'string' || !e.event.length || e.event.length > 256 || typeof e.event_payload !== 'string')
            throw new Error('Unsupported TDX runtime event format.');
        const type = new Uint8Array(4);
        new DataView(type.buffer).setUint32(0, e.event_type, true);
        const digest = await sha384(concat(type, new TextEncoder().encode(':' + e.event + ':'), bytes(e.event_payload)));
        if (e.digest && e.digest.toLowerCase() !== hex(digest))
            throw new Error('TDX runtime event digest does not match its payload.');
        mr = await sha384(concat(mr, digest));
    }
    if (hex(mr) !== hex(report.rtMr3))
        throw new Error('TDX event-log replay does not match quoted RTMR3.');
    const one = (name) => { const found = lane.filter(e => e.event === name); if (found.length !== 1)
        throw new Error(`Missing or duplicate trusted TDX event: ${name}.`); return found[0]; };
    const preparing = one('system-preparing'), boot = one('boot-mr-done'), ready = one('system-ready');
    if (lane[0] !== preparing || lane.indexOf(boot) >= lane.indexOf(ready))
        throw new Error('Invalid TDX boot event ordering.');
    for (const name of ['app-id', 'compose-hash', 'instance-id'])
        if (lane.indexOf(one(name)) >= lane.indexOf(boot))
            throw new Error(`TDX ${name} is outside the trusted boot boundary.`);
    for (const name of ['os-image-hash', 'key-provider'])
        if (lane.indexOf(one(name)) >= lane.indexOf(ready))
            throw new Error(`TDX ${name} is outside the trusted system boundary.`);
    if (!policy)
        return;
    const measurements = { mrtd: report.mrTd, rtmr0: report.rtMr0, rtmr1: report.rtMr1, rtmr2: report.rtMr2 };
    for (const [name, value] of Object.entries(measurements))
        if (hex(value) !== policy[name])
            throw new Error(`TDX ${name} does not match approved policy.`);
    for (const [event, field] of [['app-id', 'app_id'], ['compose-hash', 'compose_hash'], ['os-image-hash', 'os_image_hash']])
        if (one(event).event_payload !== policy[field])
            throw new Error(`TDX ${event} does not match approved policy.`);
};
