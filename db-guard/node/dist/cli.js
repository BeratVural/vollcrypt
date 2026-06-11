#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const prisma_1 = require("./prisma");
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
        console.error("  --db-url <url>                Database connection URL");
        console.error("  --table <table-name>          Table/collection name to migrate");
        console.error("  --column <column-name>        Column/field name to encrypt");
        console.error("  --key <32-byte-hex-key>       Encryption key (hex-encoded)");
        console.error("  --active-version <version>    Encryption key version (default: 1)");
        console.error("  --chunk-size <size>           Batch processing chunk size (default: 100)");
        console.error("  --id-col <id-col-name>        Primary key column (default: 'id' / '_id')");
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
    const dbUrl = options['db-url'];
    const table = options['table'] || options['collection'];
    const column = options['column'];
    const keyHex = options['key'];
    const activeVersion = options['active-version'] || '1';
    const chunkSize = parseInt(options['chunk-size'] || '100', 10);
    const idCol = options['id-col'] || (dbType === 'mongodb' ? '_id' : 'id');
    if (!dbType || !dbUrl || !table || !column || !keyHex) {
        console.error("Error: Missing required arguments. --db-type, --db-url, --table, --column, and --key are required.");
        process.exit(1);
    }
    if (keyHex.length !== 64) {
        console.error("Error: Key must be a 32-byte hex-encoded string (64 characters).");
        process.exit(1);
    }
    const encryptionKey = Buffer.from(keyHex, 'hex');
    console.log(`Starting shadow migration on: table/collection: "${table}", column: "${column}"`);
    console.log(`Active key version: "${activeVersion}", Batch size: ${chunkSize}`);
    if (dbType === 'postgres') {
        await migratePostgres(dbUrl, table, column, idCol, encryptionKey, activeVersion, chunkSize);
    }
    else if (dbType === 'mongodb') {
        await migrateMongo(dbUrl, table, column, idCol, encryptionKey, activeVersion, chunkSize);
    }
    else {
        console.error(`Error: Unsupported db-type "${dbType}". Supported: postgres, mongodb.`);
        process.exit(1);
    }
}
async function migratePostgres(url, table, column, idCol, key, version, chunkSize) {
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
        // 1. Count unencrypted rows (value doesn't start with VOLLVALT:)
        const countRes = await client.query(`SELECT COUNT(*) FROM "${table}" WHERE "${column}" IS NOT NULL AND "${column}" NOT LIKE 'VOLLVALT:%'`);
        const total = parseInt(countRes.rows[0].count, 10);
        if (total === 0) {
            console.log("No unencrypted records found. Migration complete!");
            return;
        }
        console.log(`Found ${total} unencrypted records. Processing...`);
        let processed = 0;
        printProgressBar(processed, total);
        while (true) {
            // 2. Fetch a batch of unencrypted rows
            const batchRes = await client.query(`SELECT "${idCol}", "${column}" FROM "${table}" WHERE "${column}" IS NOT NULL AND "${column}" NOT LIKE 'VOLLVALT:%' LIMIT $1`, [chunkSize]);
            if (batchRes.rows.length === 0) {
                break;
            }
            // 3. Encrypt and update each row
            for (const row of batchRes.rows) {
                const rawVal = row[column];
                const encryptedVal = (0, prisma_1.encryptValue)(rawVal, key, version);
                await client.query(`UPDATE "${table}" SET "${column}" = $1 WHERE "${idCol}" = $2`, [encryptedVal, row[idCol]]);
                processed++;
                printProgressBar(processed, total);
            }
        }
        console.log(`\nSuccessfully migrated ${processed} records!`);
    }
    catch (err) {
        console.error(`\nMigration failed: ${err.message}`);
    }
    finally {
        await client.end();
    }
}
async function migrateMongo(url, collectionName, field, idCol, key, version, chunkSize) {
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
        // Filter to find docs where field exists, is not null, and doesn't start with VOLLVALT:
        const filter = {
            [field]: {
                $exists: true,
                $ne: null,
                $not: /^VOLLVALT:/
            }
        };
        const total = await collection.countDocuments(filter);
        if (total === 0) {
            console.log("No unencrypted records found. Migration complete!");
            return;
        }
        console.log(`Found ${total} unencrypted records. Processing...`);
        let processed = 0;
        printProgressBar(processed, total);
        while (true) {
            const batch = await collection.find(filter).limit(chunkSize).toArray();
            if (batch.length === 0) {
                break;
            }
            for (const doc of batch) {
                const rawVal = doc[field];
                const encryptedVal = (0, prisma_1.encryptValue)(rawVal, key, version);
                await collection.updateOne({ [idCol]: doc[idCol] }, { $set: { [field]: encryptedVal } });
                processed++;
                printProgressBar(processed, total);
            }
        }
        console.log(`\nSuccessfully migrated ${processed} records!`);
    }
    catch (err) {
        console.error(`\nMigration failed: ${err.message}`);
    }
    finally {
        await client.close();
    }
}
run().catch((err) => {
    console.error(err);
    process.exit(1);
});
