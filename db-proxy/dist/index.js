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
const proxy_js_1 = require("./proxy.js");
const db_guard_1 = require("@vollcrypt/db-guard");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
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
async function runCli() {
    const args = process.argv.slice(2);
    let port = 54320;
    let dbHost = '127.0.0.1';
    let dbPort = 5432;
    let configPath = null;
    let keyString = null;
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
    }
    // Load config JSON if provided
    let config = undefined;
    if (configPath) {
        const fullPath = path.resolve(configPath);
        if (fs.existsSync(fullPath)) {
            config = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
        }
    }
    // Determine decryption keys
    let resolvedKeys = {};
    if (keyString) {
        resolvedKeys = { '1': Buffer.from(keyString, 'hex') };
    }
    else if (config && (config.key || config.kms)) {
        // Resolve keys using db-guard resolveKeys
        const dbGuardOptions = {
            key: config.key ? Buffer.from(config.key, 'hex') : undefined,
            kms: config.kms,
            models: {},
        };
        resolvedKeys = await (0, db_guard_1.resolveKeys)(dbGuardOptions);
    }
    else {
        // Fallback: Generate an ephemeral testing key if none is provided
        console.warn('No decryption key provided. Using an ephemeral testing key.');
        resolvedKeys = { '1': Buffer.alloc(32, 0x01) };
    }
    const options = {
        port,
        dbHost,
        dbPort,
        config,
        resolvedKeys,
    };
    const server = new proxy_js_1.DbProxyServer(options);
    console.log(`Starting @vollcrypt/db-proxy on port ${port}...`);
    console.log(`Forwarding to PostgreSQL at ${dbHost}:${dbPort}`);
    try {
        await server.start();
        console.log('Proxy server is running successfully.');
    }
    catch (err) {
        console.error('Failed to start proxy server:', err);
        process.exit(1);
    }
    // Handle graceful shutdown
    const shutdown = async () => {
        console.log('Shutting down proxy server...');
        await server.stop();
        // Zeroize resolved keys from memory
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
