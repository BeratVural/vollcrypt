"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.showInteractiveMenu = showInteractiveMenu;
exports.handleHybridStartup = handleHybridStartup;
const proxy_js_1 = require("./proxy.js");
const db_guard_1 = require("@vollcrypt/db-guard");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
__exportStar(require("./pg-protocol.js"), exports);
__exportStar(require("./auth.js"), exports);
__exportStar(require("./proxy.js"), exports);
// CLI entry point detection
function isMain() {
    if (typeof require !== 'undefined' && require.main === module) {
        return true;
    }
    const mainPath = process.argv[1];
    if (!mainPath)
        return false;
    try {
        const resolvedMain = fs.realpathSync(mainPath);
        const resolvedThis = fs.realpathSync(__filename);
        return resolvedMain === resolvedThis || resolvedMain.endsWith('index.js') || resolvedMain.endsWith('index.ts');
    }
    catch {
        return false;
    }
}
async function showInteractiveMenu(defaults) {
    return new Promise((resolve) => {
        if (!process.stdin.isTTY) {
            resolve(defaults);
            return;
        }
        const features = [
            { key: 'timingMitigation', label: 'Timing Attack Mitigation', enabled: defaults.minResponseTimeMs > 0 },
            { key: 'dlp', label: 'PII DLP Scanning', enabled: !defaults.noDlp },
            { key: 'waf', label: 'Database WAF Filters', enabled: !defaults.noWaf },
            { key: 'ipBanning', label: 'Gossip IP Banning', enabled: !defaults.noIpBanning },
            { key: 'fipsMode', label: 'FIPS 140-3 Boundary Compliance', enabled: defaults.fipsMode },
            { key: 'jitApprovalRequired', label: 'Just-In-Time Access Approvals', enabled: defaults.jitApprovalRequired },
            { key: 'anomalyEngine', label: 'AI Semantic Anomaly Engine', enabled: defaults.anomalyEngine }
        ];
        let cursor = 0;
        readline.emitKeypressEvents(process.stdin);
        if (process.stdin.setRawMode) {
            process.stdin.setRawMode(true);
        }
        const render = () => {
            process.stdout.write('\x1B[2J\x1B[0f');
            process.stdout.write('=== Vollcrypt DB-Proxy Feature Configuration ===\n');
            process.stdout.write('Use UP/DOWN arrows to navigate, SPACE to toggle, ENTER to confirm startup.\n\n');
            for (let i = 0; i < features.length; i++) {
                const item = features[i];
                const isCursor = i === cursor ? '> ' : '  ';
                const status = item.enabled ? '[ON]' : '[OFF]';
                process.stdout.write(`${isCursor}${item.label}: ${status}\n`);
            }
            process.stdout.write('\n');
        };
        render();
        const onKeypress = (str, key) => {
            if (key) {
                if (key.ctrl && key.name === 'c') {
                    cleanup();
                    process.exit(0);
                }
                if (key.name === 'up') {
                    cursor = (cursor - 1 + features.length) % features.length;
                    render();
                }
                else if (key.name === 'down') {
                    cursor = (cursor + 1) % features.length;
                    render();
                }
                else if (key.name === 'space') {
                    features[cursor].enabled = !features[cursor].enabled;
                    render();
                }
                else if (key.name === 'return' || key.name === 'enter') {
                    cleanup();
                    const result = {
                        minResponseTimeMs: features[0].enabled ? (defaults.minResponseTimeMs || 15) : 0,
                        noDlp: !features[1].enabled,
                        noWaf: !features[2].enabled,
                        noIpBanning: !features[3].enabled,
                        fipsMode: features[4].enabled,
                        jitApprovalRequired: features[5].enabled,
                        anomalyEngine: features[6].enabled,
                    };
                    process.stdout.write('\x1B[2J\x1B[0f');
                    resolve(result);
                }
            }
        };
        const cleanup = () => {
            process.stdin.removeListener('keypress', onKeypress);
            if (process.stdin.setRawMode) {
                process.stdin.setRawMode(false);
            }
        };
        process.stdin.on('keypress', onKeypress);
    });
}
async function handleHybridStartup(defaults) {
    return new Promise((resolve) => {
        if (!process.stdin.isTTY) {
            resolve(defaults);
            return;
        }
        const features = { ...defaults };
        let timeLeft = 3;
        let timer;
        readline.emitKeypressEvents(process.stdin);
        if (process.stdin.setRawMode) {
            process.stdin.setRawMode(true);
        }
        const printCountdown = () => {
            process.stdout.write(`\r\x1B[KStarting proxy in ${timeLeft}s... Press SPACE to configure, ENTER to start now.`);
        };
        printCountdown();
        const onKeypress = async (str, key) => {
            if (key) {
                if (key.ctrl && key.name === 'c') {
                    cleanup();
                    process.exit(0);
                }
                if (key.name === 'space') {
                    cleanup();
                    process.stdout.write('\n');
                    const selected = await showInteractiveMenu(features);
                    resolve(selected);
                }
                else if (key.name === 'return' || key.name === 'enter') {
                    cleanup();
                    process.stdout.write('\n');
                    resolve(features);
                }
            }
        };
        const cleanup = () => {
            clearInterval(timer);
            process.stdin.removeListener('keypress', onKeypress);
            if (process.stdin.setRawMode) {
                process.stdin.setRawMode(false);
            }
        };
        timer = setInterval(() => {
            timeLeft--;
            if (timeLeft <= 0) {
                cleanup();
                process.stdout.write('\n');
                resolve(features);
            }
            else {
                printCountdown();
            }
        }, 1000);
        process.stdin.on('keypress', onKeypress);
    });
}
async function runCli() {
    const args = process.argv.slice(2);
    let port = 54320;
    let dbHost = '127.0.0.1';
    let dbPort = 5432;
    let configPath = null;
    let keyString = null;
    // Feature toggles
    let minResponseTimeMs = 15;
    let noDlp = false;
    let noWaf = false;
    let noIpBanning = false;
    let fipsMode = false;
    let jitApprovalRequired = false;
    let anomalyEngine = false;
    let dbType = 'postgres';
    let gossipPort;
    let peers;
    let interactiveMode = null;
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--port' && args[i + 1]) {
            port = parseInt(args[i + 1], 10);
            i++;
        }
        else if (args[i] === '--db-host' && args[i + 1]) {
            dbHost = args[i + 1];
            i++;
        }
        else if (args[i] === '--db-port' && args[i + 1]) {
            dbPort = parseInt(args[i + 1], 10);
            i++;
        }
        else if (args[i] === '--config' && args[i + 1]) {
            configPath = args[i + 1];
            i++;
        }
        else if (args[i] === '--key' && args[i + 1]) {
            keyString = args[i + 1];
            i++;
        }
        else if (args[i] === '--min-response-time' && args[i + 1]) {
            minResponseTimeMs = parseInt(args[i + 1], 10);
            i++;
        }
        else if (args[i] === '--no-timing-mitigation') {
            minResponseTimeMs = 0;
        }
        else if (args[i] === '--no-dlp') {
            noDlp = true;
        }
        else if (args[i] === '--no-waf') {
            noWaf = true;
        }
        else if (args[i] === '--no-ip-banning') {
            noIpBanning = true;
        }
        else if (args[i] === '--fips') {
            fipsMode = true;
        }
        else if (args[i] === '--no-fips') {
            fipsMode = false;
        }
        else if (args[i] === '--jit') {
            jitApprovalRequired = true;
        }
        else if (args[i] === '--no-jit') {
            jitApprovalRequired = false;
        }
        else if (args[i] === '--anomaly') {
            anomalyEngine = true;
        }
        else if (args[i] === '--no-anomaly') {
            anomalyEngine = false;
        }
        else if (args[i] === '--db-type' && args[i + 1]) {
            dbType = args[i + 1];
            i++;
        }
        else if (args[i] === '--gossip-port' && args[i + 1]) {
            gossipPort = parseInt(args[i + 1], 10);
            i++;
        }
        else if (args[i] === '--peers' && args[i + 1]) {
            peers = args[i + 1].split(',');
            i++;
        }
        else if (args[i] === '--interactive' || args[i] === '-i') {
            interactiveMode = true;
        }
        else if (args[i] === '--non-interactive' || args[i] === '-y' || args[i] === '--yes' || args[i] === '-n') {
            interactiveMode = false;
        }
    }
    // Handle hybrid, interactive, or non-interactive startup
    if (interactiveMode === true) {
        const selected = await showInteractiveMenu({
            minResponseTimeMs,
            noDlp,
            noWaf,
            noIpBanning,
            fipsMode,
            jitApprovalRequired,
            anomalyEngine,
        });
        minResponseTimeMs = selected.minResponseTimeMs;
        noDlp = selected.noDlp;
        noWaf = selected.noWaf;
        noIpBanning = selected.noIpBanning;
        fipsMode = selected.fipsMode;
        jitApprovalRequired = selected.jitApprovalRequired;
        anomalyEngine = selected.anomalyEngine;
    }
    else if (interactiveMode === null && process.stdin.isTTY) {
        const selected = await handleHybridStartup({
            minResponseTimeMs,
            noDlp,
            noWaf,
            noIpBanning,
            fipsMode,
            jitApprovalRequired,
            anomalyEngine,
        });
        minResponseTimeMs = selected.minResponseTimeMs;
        noDlp = selected.noDlp;
        noWaf = selected.noWaf;
        noIpBanning = selected.noIpBanning;
        fipsMode = selected.fipsMode;
        jitApprovalRequired = selected.jitApprovalRequired;
        anomalyEngine = selected.anomalyEngine;
    }
    // Load config JSON if provided
    let config = undefined;
    if (configPath) {
        const fullPath = path.resolve(configPath);
        if (fs.existsSync(fullPath)) {
            config = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
        }
    }
    // Merge config overrides
    if (config) {
        if (!config.firewall)
            config.firewall = {};
        if (fipsMode)
            config.firewall.fipsMode = true;
        if (jitApprovalRequired)
            config.firewall.jitApprovalRequired = true;
        if (anomalyEngine) {
            if (!config.firewall.anomalyEngine)
                config.firewall.anomalyEngine = {};
            config.firewall.anomalyEngine.enabled = true;
        }
    }
    else {
        config = {
            firewall: {
                fipsMode,
                jitApprovalRequired,
                anomalyEngine: { enabled: anomalyEngine },
            }
        };
    }
    // Determine decryption keys
    let resolvedKeys = {};
    if (keyString) {
        resolvedKeys = { '1': Buffer.from(keyString, 'hex') };
    }
    else if (config && (config.key || config.kms)) {
        const dbGuardOptions = {
            key: config.key ? Buffer.from(config.key, 'hex') : undefined,
            kms: config.kms,
            models: {},
        };
        resolvedKeys = await (0, db_guard_1.resolveKeys)(dbGuardOptions);
    }
    else {
        console.warn('No decryption key provided. Using an ephemeral testing key.');
        resolvedKeys = { '1': Buffer.alloc(32, 0x01) };
    }
    const options = {
        port,
        dbHost,
        dbPort,
        config,
        resolvedKeys,
        minResponseTimeMs,
        gossipPort,
        peers,
        noDlp,
        noWaf,
        noIpBanning,
        dbType,
        fipsMode,
    };
    const server = new proxy_js_1.DbProxyServer(options);
    console.log(`Starting @vollcrypt/db-proxy on port ${port}...`);
    console.log(`Forwarding to ${dbType.toUpperCase()} at ${dbHost}:${dbPort}`);
    console.log(`Active Features:`);
    console.log(`- Timing Attack Mitigation: ${minResponseTimeMs > 0 ? `Enabled (${minResponseTimeMs}ms)` : 'Disabled'}`);
    console.log(`- PII DLP Scanner: ${!noDlp ? 'Enabled' : 'Disabled'}`);
    console.log(`- WAF Security Engine: ${!noWaf ? 'Enabled' : 'Disabled'}`);
    console.log(`- Distributed Gossip IP Banning: ${!noIpBanning ? 'Enabled' : 'Disabled'}`);
    console.log(`- FIPS 140-3 Compliance: ${fipsMode ? 'Enabled' : 'Disabled'}`);
    console.log(`- Just-In-Time Access Approvals: ${jitApprovalRequired ? 'Enabled' : 'Disabled'}`);
    console.log(`- AI Semantic Anomaly Engine: ${anomalyEngine ? 'Enabled' : 'Disabled'}`);
    try {
        await server.start();
        console.log('Proxy server is running successfully.');
    }
    catch (err) {
        console.error('Failed to start proxy server:', err);
        process.exit(1);
    }
    const shutdown = async () => {
        console.log('Shutting down proxy server...');
        await server.stop();
        for (const key of Object.values(resolvedKeys)) {
            key.fill(0);
        }
        console.log('Shutdown complete.');
        process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}
if (isMain()) {
    runCli().catch((err) => {
        console.error('CLI error:', err);
        process.exit(1);
    });
}
