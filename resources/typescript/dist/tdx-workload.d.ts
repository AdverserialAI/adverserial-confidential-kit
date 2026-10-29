import type { TDXPolicy } from './runtime-policy.js';
export type TDXReport = {
    mrTd: Uint8Array;
    rtMr0: Uint8Array;
    rtMr1: Uint8Array;
    rtMr2: Uint8Array;
    rtMr3: Uint8Array;
    tdAttributes: Uint8Array;
};
/** dstack v0.5.x event-log V1. See cc-eventlog/src/runtime_events.rs at v0.5.9. */
export declare const verifyTDXWorkload: (report: TDXReport, eventLog: unknown, policy?: TDXPolicy) => Promise<void>;
