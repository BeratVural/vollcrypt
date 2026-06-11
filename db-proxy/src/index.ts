import { DbProxyServer, DbProxyOptions } from './proxy.js';
import { resolveKeys } from '@vollcrypt/db-guard';
import * as fs from 'fs';
import * as path from 'path';

export * from './pg-protocol.js';
export * from './auth.js';
export * from './proxy.js';

// CLI entry point detection
function isMain(): boolean {
  if (typeof require !== 'undefined' && require.main === module) {
    return true;
  }
  const mainPath = process.argv[1];
  if (!mainPath) return false;
  
  try {
    const resolvedMain = fs.realpathSync(mainPath);
    const resolvedThis = fs.realpathSync(__filename);
    return resolvedMain === resolvedThis || resolvedMain.endsWith('index.js') || resolvedMain.endsWith('index.ts');
  } catch {
    return false;
  }
}

async function runCli() {
  const args = process.argv.slice(2);
  let port = 54320;
  let dbHost = '127.0.0.1';
  let dbPort = 5432;
  let configPath: string | null = null;
  let keyString: string | null = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === '--db-host' && args[i + 1]) {
      dbHost = args[i + 1];
      i++;
    } else if (args[i] === '--db-port' && args[i + 1]) {
      dbPort = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === '--config' && args[i + 1]) {
      configPath = args[i + 1];
      i++;
    } else if (args[i] === '--key' && args[i + 1]) {
      keyString = args[i + 1];
      i++;
    }
  }

  // Load config JSON if provided
  let config: any = undefined;
  if (configPath) {
    const fullPath = path.resolve(configPath);
    if (fs.existsSync(fullPath)) {
      config = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    }
  }

  // Determine decryption keys
  let resolvedKeys: Record<string, Buffer> = {};
  if (keyString) {
    resolvedKeys = { '1': Buffer.from(keyString, 'hex') };
  } else if (config && (config.key || config.kms)) {
    // Resolve keys using db-guard resolveKeys
    const dbGuardOptions = {
      key: config.key ? Buffer.from(config.key, 'hex') : undefined,
      kms: config.kms,
      models: {},
    };
    resolvedKeys = await resolveKeys(dbGuardOptions);
  } else {
    // Fallback: Generate an ephemeral testing key if none is provided
    console.warn('No decryption key provided. Using an ephemeral testing key.');
    resolvedKeys = { '1': Buffer.alloc(32, 0x01) };
  }

  const options: DbProxyOptions = {
    port,
    dbHost,
    dbPort,
    config,
    resolvedKeys,
  };

  const server = new DbProxyServer(options);

  console.log(`Starting @vollcrypt/db-proxy on port ${port}...`);
  console.log(`Forwarding to PostgreSQL at ${dbHost}:${dbPort}`);

  try {
    await server.start();
    console.log('Proxy server is running successfully.');
  } catch (err) {
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
