export * from './pg-protocol.js';
export * from './auth.js';
export * from './proxy.js';
export declare function showInteractiveMenu(defaults: {
    minResponseTimeMs: number;
    noAttestation: boolean;
    noDlp: boolean;
    noWaf: boolean;
    noIpBanning: boolean;
    fipsMode: boolean;
    jitApprovalRequired: boolean;
    anomalyEngine: boolean;
}): Promise<any>;
export declare function handleHybridStartup(defaults: {
    minResponseTimeMs: number;
    noAttestation: boolean;
    noDlp: boolean;
    noWaf: boolean;
    noIpBanning: boolean;
    fipsMode: boolean;
    jitApprovalRequired: boolean;
    anomalyEngine: boolean;
}): Promise<any>;
