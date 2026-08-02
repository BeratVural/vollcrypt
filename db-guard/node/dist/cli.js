#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_MIGRATION_OPTIONS = void 0;
exports.parsePositiveIntegerOption = parsePositiveIntegerOption;
exports.parseMigrationDirection = parseMigrationDirection;
exports.assertSafeIdentifier = assertSafeIdentifier;
exports.buildPostgresBatchSelectSql = buildPostgresBatchSelectSql;
exports.migratePostgresWithClient = migratePostgresWithClient;
exports.migratePostgres = migratePostgres;
exports.migrateMongoCollection = migrateMongoCollection;
exports.migrateMongo = migrateMongo;
const errors_1 = require("./errors");
const security_1 = require("./security");
exports.DEFAULT_MIGRATION_OPTIONS = {
    direction: 'up',
    statementTimeoutMs: 30_000,
    lockTimeoutMs: 5_000,
    mongoMaxTimeMs: 30_000,
};
function parsePositiveIntegerOption(value, fallback, label) {
    if (value === undefined)
        return fallback;
    const parsed = Number.parseInt(value, 10);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw (0, errors_1.dbGuardError)(`${label} must be a positive integer.`);
    }
    return parsed;
}
function parseMigrationDirection(value) {
    const direction = value || 'up';
    if (direction !== 'up' && direction !== 'down') {
        throw (0, errors_1.dbGuardError)(`--direction must be 'up' or 'down'.`);
    }
    return direction;
}
function assertSafeIdentifier(identifier, label) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
        throw (0, errors_1.dbGuardError)(`${label} must be a simple SQL/Mongo identifier matching [A-Za-z_][A-Za-z0-9_]*.`);
    }
    return identifier;
}
function quoteIdentifier(identifier) {
    return `"${assertSafeIdentifier(identifier, 'identifier')}"`;
}
function transformMigrationValue(rawVal, key, version, direction) {
    if (direction === 'up') {
        return (0, security_1.encryptValue)(rawVal, key, version);
    }
    return (0, security_1.decryptValue)(rawVal, { [version]: key });
}
function postgresColumnPredicate(columnSql, direction) {
    if (direction === 'up') {
        return `${columnSql} IS NOT NULL AND ${columnSql} NOT LIKE 'VOLLVALT:%'`;
    }
    return `${columnSql} LIKE 'VOLLVALT:%'`;
}
function buildPostgresBatchSelectSql(table, column, idCol, direction, hasLastId) {
    const tableSql = quoteIdentifier(table);
    const columnSql = quoteIdentifier(column);
    const idSql = quoteIdentifier(idCol);
    const keysetClause = hasLastId ? ` AND ${idSql} > $1` : '';
    const limitParam = hasLastId ? '$2' : '$1';
    return `SELECT ${idSql}, ${columnSql} FROM ${tableSql} WHERE ${postgresColumnPredicate(columnSql, direction)}${keysetClause} ORDER BY ${idSql} ASC LIMIT ${limitParam}`;
}
function postgresCountSql(table, column, direction) {
    const tableSql = quoteIdentifier(table);
    const columnSql = quoteIdentifier(column);
    return `SELECT COUNT(*) FROM ${tableSql} WHERE ${postgresColumnPredicate(columnSql, direction)}`;
}
function postgresUpdateSql(table, column, idCol) {
    return `UPDATE ${quoteIdentifier(table)} SET ${quoteIdentifier(column)} = $1 WHERE ${quoteIdentifier(idCol)} = $2`;
}
function timeoutSql(kind, ms, local) {
    const scope = local ? 'SET LOCAL' : 'SET';
    return `${scope} ${kind} = '${ms}ms'`;
}
function mongoBaseFilter(field, direction) {
    assertSafeIdentifier(field, 'field');
    if (direction === 'up') {
        return {
            [field]: {
                $exists: true,
                $ne: null,
                $not: /^VOLLVALT:/,
            },
        };
    }
    return {
        [field]: /^VOLLVALT:/,
    };
}
function mongoBatchFilter(field, idCol, direction, lastId) {
    assertSafeIdentifier(idCol, 'id column');
    const base = mongoBaseFilter(field, direction);
    if (lastId === undefined)
        return base;
    return { $and: [base, { [idCol]: { $gt: lastId } }] };
}
function readSecretFile(filePath, label) {
    const fs = require('fs');
    const path = require('path');
    const fullPath = path.resolve(filePath);
    if (!fs.existsSync(fullPath)) {
        throw (0, errors_1.dbGuardError)(`${label} file not found at ${fullPath}`);
    }
    return fs.readFileSync(fullPath, 'utf8').trim();
}
function getRequiredSecret(options, envName, fileOption, label) {
    if (options[label]) {
        throw (0, errors_1.dbGuardError)(`--${label} is not allowed because it exposes secrets in process lists. Use ${envName} or --${fileOption}.`);
    }
    if (process.env[envName]) {
        return process.env[envName].trim();
    }
    if (options[fileOption]) {
        return readSecretFile(options[fileOption], label);
    }
    throw (0, errors_1.dbGuardError)(`Missing ${label}. Set ${envName} or pass --${fileOption} <path>.`);
}
function printProgressBar(current, total) {
    const percentage = Math.min(100, Math.floor((current / total) * 100));
    const barLength = 40;
    const completedLength = Math.floor((percentage / 100) * barLength);
    const remainingLength = barLength - completedLength;
    const progressBar = '='.repeat(completedLength) + '>'.repeat(completedLength > 0 && remainingLength > 0 ? 1 : 0) + ' '.repeat(Math.max(0, remainingLength - (completedLength > 0 && remainingLength > 0 ? 1 : 0)));
    process.stdout.write(`\rProgress: [${progressBar}] ${percentage}% (${current}/${total} records)`);
}
async function run() {
    const args = process.argv.slice(2);
    if (args.length === 0 || (args[0] !== 'migrate' && args[0] !== 'compliance')) {
        console.error("Usage: vollcrypt-db-guard <command> [options]");
        console.error("\nCommands:");
        console.error("  migrate       Run shadow database migrations");
        console.error("  compliance    Scan database configurations and generate a compliance HTML scorecard");
        console.error("\nMigrate Options:");
        console.error("  --db-type <postgres|mongodb>  Database type");
        console.error("  --db-url-file <path>          File containing database connection URL (or VOLLCRYPT_DB_GUARD_DB_URL env)");
        console.error("  --table <table-name>          Table/collection name to migrate");
        console.error("  --column <column-name>        Column/field name to encrypt");
        console.error("  --key-file <path>             File containing 32-byte hex key (or VOLLCRYPT_DB_GUARD_KEY_HEX env)");
        console.error("  --active-version <version>    Encryption key version (default: 1)");
        console.error("  --chunk-size <size>           Batch processing chunk size (default: 100)");
        console.error("  --id-col <id-col-name>        Primary key column (default: 'id' / '_id')");
        console.error("  --direction <up|down>         Encrypt plaintext values or rollback encrypted values (default: up)");
        console.error("  --statement-timeout-ms <ms>   PostgreSQL statement timeout (default: 30000)");
        console.error("  --lock-timeout-ms <ms>        PostgreSQL lock timeout (default: 5000)");
        console.error("  --mongo-max-time-ms <ms>      MongoDB operation maxTimeMS (default: 30000)");
        console.error("\nCompliance Options:");
        console.error("  --config <path-to-json-file>  Path to configuration file");
        console.error("  --output <output-html-path>   Path to write HTML compliance report (default: compliance-report.html)");
        process.exit(1);
    }
    if (args[0] === 'compliance') {
        const options = {};
        for (let i = 1; i < args.length; i += 2) {
            if (args[i] && args[i + 1]) {
                const key = args[i].replace(/^--/, '');
                const val = args[i + 1];
                options[key] = val;
            }
        }
        const configPath = options['config'];
        const outputPath = options['output'] || 'compliance-report.html';
        if (!configPath) {
            console.error("Error: --config <path-to-json-file> is required for compliance scan.");
            process.exit(1);
        }
        const fs = require('fs');
        const path = require('path');
        try {
            const fullPath = path.resolve(configPath);
            if (!fs.existsSync(fullPath)) {
                console.error(`Error: Configuration file not found at ${fullPath}`);
                process.exit(1);
            }
            const raw = fs.readFileSync(fullPath, 'utf8');
            const config = JSON.parse(raw);
            const { generateComplianceHtmlReport } = require('./compliance');
            const html = generateComplianceHtmlReport(config);
            const outFullPath = path.resolve(outputPath);
            fs.writeFileSync(outFullPath, html, 'utf8');
            console.log(`Compliance report generated successfully at ${outFullPath}`);
        }
        catch (err) {
            console.error(`Error generating compliance report: ${err.message}`);
            process.exit(1);
        }
        return;
    }
    // Parse arguments
    const options = {};
    for (let i = 1; i < args.length; i += 2) {
        if (args[i] && args[i + 1]) {
            const key = args[i].replace(/^--/, '');
            const val = args[i + 1];
            options[key] = val;
        }
    }
    const dbType = options['db-type'];
    let dbUrl = '';
    let keyHex = '';
    try {
        dbUrl = getRequiredSecret(options, 'VOLLCRYPT_DB_GUARD_DB_URL', 'db-url-file', 'db-url');
        keyHex = getRequiredSecret(options, 'VOLLCRYPT_DB_GUARD_KEY_HEX', 'key-file', 'key');
    }
    catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
    const table = options['table'] || options['collection'];
    const column = options['column'];
    const activeVersion = options['active-version'] || '1';
    let chunkSize = 100;
    let migrationOptions = exports.DEFAULT_MIGRATION_OPTIONS;
    try {
        chunkSize = parsePositiveIntegerOption(options['chunk-size'], 100, '--chunk-size');
        migrationOptions = {
            direction: parseMigrationDirection(options['direction']),
            statementTimeoutMs: parsePositiveIntegerOption(options['statement-timeout-ms'], exports.DEFAULT_MIGRATION_OPTIONS.statementTimeoutMs, '--statement-timeout-ms'),
            lockTimeoutMs: parsePositiveIntegerOption(options['lock-timeout-ms'], exports.DEFAULT_MIGRATION_OPTIONS.lockTimeoutMs, '--lock-timeout-ms'),
            mongoMaxTimeMs: parsePositiveIntegerOption(options['mongo-max-time-ms'], exports.DEFAULT_MIGRATION_OPTIONS.mongoMaxTimeMs, '--mongo-max-time-ms'),
        };
    }
    catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
    const idCol = options['id-col'] || (dbType === 'mongodb' ? '_id' : 'id');
    if (!dbType || !dbUrl || !table || !column || !keyHex) {
        console.error("Error: Missing required arguments. --db-type, secret db URL, --table, --column, and secret key are required.");
        process.exit(1);
    }
    if (keyHex.length !== 64) {
        console.error("Error: Key must be a 32-byte hex-encoded string (64 characters).");
        process.exit(1);
    }
    const encryptionKey = Buffer.from(keyHex, 'hex');
    console.log(`Starting shadow migration on: table/collection: "${table}", column: "${column}"`);
    console.log(`Active key version: "${activeVersion}", Batch size: ${chunkSize}, Direction: ${migrationOptions.direction}`);
    if (dbType === 'postgres') {
        await migratePostgres(dbUrl, table, column, idCol, encryptionKey, activeVersion, chunkSize, migrationOptions);
    }
    else if (dbType === 'mongodb') {
        await migrateMongo(dbUrl, table, column, idCol, encryptionKey, activeVersion, chunkSize, migrationOptions);
    }
    else {
        console.error(`Error: Unsupported db-type "${dbType}". Supported: postgres, mongodb.`);
        process.exit(1);
    }
}
async function migratePostgresWithClient(client, table, column, idCol, key, version, chunkSize, options = exports.DEFAULT_MIGRATION_OPTIONS) {
    assertSafeIdentifier(table, 'table');
    assertSafeIdentifier(column, 'column');
    assertSafeIdentifier(idCol, 'id column');
    await client.query(timeoutSql('statement_timeout', options.statementTimeoutMs, false));
    await client.query(timeoutSql('lock_timeout', options.lockTimeoutMs, false));
    const countRes = await client.query(postgresCountSql(table, column, options.direction));
    const total = parseInt(countRes.rows[0].count, 10);
    if (total === 0) {
        console.log('No matching records found. Migration complete!');
        return 0;
    }
    console.log(`Found ${total} matching records. Processing...`);
    let processed = 0;
    let lastId = undefined;
    printProgressBar(processed, total);
    while (true) {
        await client.query('BEGIN');
        try {
            await client.query(timeoutSql('statement_timeout', options.statementTimeoutMs, true));
            await client.query(timeoutSql('lock_timeout', options.lockTimeoutMs, true));
            const hasLastId = lastId !== undefined;
            const batchRes = await client.query(buildPostgresBatchSelectSql(table, column, idCol, options.direction, hasLastId), hasLastId ? [lastId, chunkSize] : [chunkSize]);
            if (batchRes.rows.length === 0) {
                await client.query('COMMIT');
                break;
            }
            for (const row of batchRes.rows) {
                const rawVal = row[column];
                const migratedVal = transformMigrationValue(rawVal, key, version, options.direction);
                await client.query(postgresUpdateSql(table, column, idCol), [migratedVal, row[idCol]]);
                processed++;
                printProgressBar(processed, total);
            }
            lastId = batchRes.rows[batchRes.rows.length - 1][idCol];
            await client.query('COMMIT');
        }
        catch (err) {
            await client.query('ROLLBACK').catch(() => undefined);
            throw err;
        }
    }
    console.log(`\nSuccessfully migrated ${processed} records!`);
    return processed;
}
async function migratePostgres(url, table, column, idCol, key, version, chunkSize, options = exports.DEFAULT_MIGRATION_OPTIONS) {
    let Client;
    try {
        Client = require('pg').Client;
    }
    catch (err) {
        console.error("Error: The 'pg' package is not installed. Please install 'pg' to run migrations on PostgreSQL.");
        process.exit(1);
    }
    const client = new Client({ connectionString: url });
    await client.connect();
    try {
        return await migratePostgresWithClient(client, table, column, idCol, key, version, chunkSize, options);
    }
    catch (err) {
        console.error(`\nMigration failed: ${err.message}`);
        throw err;
    }
    finally {
        await client.end();
    }
}
async function migrateMongoCollection(collection, collectionName, field, idCol, key, version, chunkSize, options = exports.DEFAULT_MIGRATION_OPTIONS) {
    assertSafeIdentifier(collectionName, 'collection');
    assertSafeIdentifier(field, 'field');
    assertSafeIdentifier(idCol, 'id column');
    const total = await collection.countDocuments(mongoBaseFilter(field, options.direction), { maxTimeMS: options.mongoMaxTimeMs });
    if (total === 0) {
        console.log('No matching records found. Migration complete!');
        return 0;
    }
    console.log(`Found ${total} matching records. Processing...`);
    let processed = 0;
    let lastId = undefined;
    printProgressBar(processed, total);
    while (true) {
        const filter = mongoBatchFilter(field, idCol, options.direction, lastId);
        const batch = await collection
            .find(filter)
            .sort({ [idCol]: 1 })
            .limit(chunkSize)
            .maxTimeMS(options.mongoMaxTimeMs)
            .toArray();
        if (batch.length === 0) {
            break;
        }
        for (const doc of batch) {
            const rawVal = doc[field];
            const migratedVal = transformMigrationValue(rawVal, key, version, options.direction);
            await collection.updateOne({ [idCol]: doc[idCol] }, { $set: { [field]: migratedVal } }, { maxTimeMS: options.mongoMaxTimeMs });
            processed++;
            printProgressBar(processed, total);
        }
        lastId = batch[batch.length - 1][idCol];
    }
    console.log(`\nSuccessfully migrated ${processed} records!`);
    return processed;
}
async function migrateMongo(url, collectionName, field, idCol, key, version, chunkSize, options = exports.DEFAULT_MIGRATION_OPTIONS) {
    let MongoClient;
    try {
        MongoClient = require('mongodb').MongoClient;
    }
    catch (err) {
        console.error("Error: The 'mongodb' package is not installed. Please install 'mongodb' to run migrations on MongoDB.");
        process.exit(1);
    }
    const client = new MongoClient(url);
    await client.connect();
    try {
        const db = client.db();
        const collection = db.collection(collectionName);
        return await migrateMongoCollection(collection, collectionName, field, idCol, key, version, chunkSize, options);
    }
    catch (err) {
        console.error(`\nMigration failed: ${err.message}`);
        throw err;
    }
    finally {
        await client.close();
    }
}
if (require.main === module) {
    run().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
