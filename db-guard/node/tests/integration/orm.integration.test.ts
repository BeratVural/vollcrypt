import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import mongoose, { Schema } from 'mongoose';
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { eq } from 'drizzle-orm';
import { pgTable, serial } from 'drizzle-orm/pg-core';
import { DataSource, EntitySchema } from 'typeorm';
import { prismaDbGuard } from '../../src/prisma';
import { mongooseDbGuard } from '../../src/mongoose';
import { createDrizzleGuard } from '../../src/drizzle';
import { createTypeOrmSubscriber } from '../../src/typeorm';

const enabled = process.env.RUN_DB_INTEGRATION === '1';
const databaseUrl = process.env.DATABASE_URL || '';
const mongoUrl = process.env.MONGODB_URI || '';
const keyV1 = Buffer.alloc(32, 0x11);
const keyV2 = Buffer.alloc(32, 0x22);
const wrongKey = Buffer.alloc(32, 0x7f);
const plaintext = 'integration-secret-4111111111111111';

function unrestricted<T extends object>(options: T): T {
  return { ...options, allowUnrestrictedDecrypt: true };
}

function assertCiphertextAtRest(value: unknown) {
  assert.equal(typeof value, 'string');
  assert.match(value as string, /^VOLLVALT:v[12]:/);
  assert.equal((value as string).includes(plaintext), false);
}

describe('real ORM and database integration', { skip: !enabled }, () => {
  let pool: Pool;

  before(async () => {
    assert.ok(databaseUrl, 'DATABASE_URL is required');
    assert.ok(mongoUrl, 'MONGODB_URI is required');
    pool = new Pool({ connectionString: databaseUrl });
    await pool.query('SELECT 1');
  });

  after(async () => {
    await pool?.end();
  });

  test('Prisma stores ciphertext, decrypts authorized reads, rejects a wrong key, and rotates key versions', async () => {
    const { PrismaClient } = require('./generated/prisma-client');
    const base = new PrismaClient();
    const guardV1 = base.$extends(prismaDbGuard(unrestricted({
      models: { GuardPrismaRecord: ['secret'] },
      key: keyV1
    }) as any));

    try {
      await base.guardPrismaRecord.deleteMany();
      const created = await guardV1.guardPrismaRecord.create({ data: { secret: plaintext } });
      assert.equal(created.secret, plaintext);

      const rawV1 = await base.$queryRawUnsafe<Array<{ secret: string }>>(
        'SELECT secret FROM "GuardPrismaRecord" WHERE id = $1',
        created.id
      );
      assertCiphertextAtRest(rawV1[0].secret);
      assert.match(rawV1[0].secret, /^VOLLVALT:v1:/);

      const wrongBase = new PrismaClient();
      const wrongGuard = wrongBase.$extends(prismaDbGuard(unrestricted({
        models: { GuardPrismaRecord: ['secret'] },
        key: wrongKey
      }) as any));
      try {
        await assert.rejects(
          wrongGuard.guardPrismaRecord.findUnique({ where: { id: created.id } }),
          /decrypt|authentication|Unsupported state/i
        );
      } finally {
        await wrongBase.$disconnect();
      }

      const rotatingBase = new PrismaClient();
      const rotatingGuard = rotatingBase.$extends(prismaDbGuard(unrestricted({
        models: { GuardPrismaRecord: ['secret'] },
        kms: { activeKeyVersion: '2' }
      }) as any, { '1': keyV1, '2': keyV2 }));
      try {
        const oldValue = await rotatingGuard.guardPrismaRecord.findUnique({ where: { id: created.id } });
        assert.equal(oldValue?.secret, plaintext);
        await rotatingGuard.guardPrismaRecord.update({
          where: { id: created.id },
          data: { secret: plaintext }
        });
        const rawV2 = await rotatingBase.$queryRawUnsafe<Array<{ secret: string }>>(
          'SELECT secret FROM "GuardPrismaRecord" WHERE id = $1',
          created.id
        );
        assert.match(rawV2[0].secret, /^VOLLVALT:v2:/);
      } finally {
        await rotatingBase.$disconnect();
      }
    } finally {
      await base.$disconnect();
    }
  });

  test('Mongoose plugin stores ciphertext and fails closed with an unauthorized key', async () => {
    const connection = await mongoose.createConnection(mongoUrl, {
      dbName: 'vollcrypt_guard_integration'
    }).asPromise();

    try {
      await connection.dropDatabase();
      const schema = new Schema({ secret: { type: String, required: true } });
      schema.plugin(mongooseDbGuard as any, unrestricted({ key: keyV1, fields: ['secret'] }));
      const GuardRecord = connection.model('GuardMongooseRecord', schema, 'guard_mongoose_records');

      const created = await GuardRecord.create({ secret: plaintext });
      const raw = await connection.collection('guard_mongoose_records').findOne({ _id: created._id });
      assertCiphertextAtRest(raw?.secret);

      const authorized = await GuardRecord.findById(created._id);
      assert.equal(authorized?.secret, plaintext);

      const wrongSchema = new Schema({ secret: { type: String, required: true } });
      wrongSchema.plugin(mongooseDbGuard as any, unrestricted({ key: wrongKey, fields: ['secret'] }));
      const WrongGuardRecord = connection.model(
        'WrongGuardMongooseRecord',
        wrongSchema,
        'guard_mongoose_records'
      );
      await assert.rejects(
        WrongGuardRecord.findById(created._id),
        /decrypt|authentication|Unsupported state/i
      );
    } finally {
      await connection.close();
    }
  });

  test('Drizzle custom type encrypts through the PostgreSQL driver and rejects a wrong key', async () => {
    await pool.query('DROP TABLE IF EXISTS guard_drizzle_records');
    await pool.query('CREATE TABLE guard_drizzle_records (id SERIAL PRIMARY KEY, secret TEXT NOT NULL)');

    const guard = createDrizzleGuard(unrestricted({ key: keyV1 }) as any);
    const records = pgTable('guard_drizzle_records', {
      id: serial('id').primaryKey(),
      secret: guard.pgText('secret', 'GuardDrizzleRecord.secret').notNull()
    });
    const db = drizzle(pool);
    const [created] = await db.insert(records).values({ secret: plaintext }).returning();
    assert.equal(created.secret, plaintext);

    const raw = await pool.query<{ secret: string }>(
      'SELECT secret FROM guard_drizzle_records WHERE id = $1',
      [created.id]
    );
    assertCiphertextAtRest(raw.rows[0].secret);

    const [authorized] = await db.select().from(records).where(eq(records.id, created.id));
    assert.equal(authorized.secret, plaintext);

    const wrongGuard = createDrizzleGuard(unrestricted({ key: wrongKey }) as any);
    const wrongRecords = pgTable('guard_drizzle_records', {
      id: serial('id').primaryKey(),
      secret: wrongGuard.pgText('secret', 'GuardDrizzleRecord.secret').notNull()
    });
    await assert.rejects(
      db.select().from(wrongRecords).where(eq(wrongRecords.id, created.id)),
      /decrypt|authentication|Unsupported state/i
    );
  });

  test('TypeORM subscriber stores ciphertext and rejects a wrong key', async () => {
    await pool.query('DROP TABLE IF EXISTS guard_typeorm_records');
    await pool.query('CREATE TABLE guard_typeorm_records (id SERIAL PRIMARY KEY, secret TEXT NOT NULL)');

    const recordSchema = new EntitySchema({
      name: 'GuardTypeOrmRecord',
      tableName: 'guard_typeorm_records',
      columns: {
        id: { type: Number, primary: true, generated: true },
        secret: { type: String }
      }
    });
    const source = new DataSource({
      type: 'postgres',
      url: databaseUrl,
      entities: [recordSchema],
      subscribers: [createTypeOrmSubscriber(unrestricted({
        key: keyV1,
        entities: { GuardTypeOrmRecord: ['secret'] }
      }) as any)],
      synchronize: false
    });

    await source.initialize();
    try {
      const repo = source.getRepository('GuardTypeOrmRecord');
      const saved = await repo.save({ secret: plaintext });
      const raw = await source.query('SELECT secret FROM guard_typeorm_records WHERE id = $1', [saved.id]);
      assertCiphertextAtRest(raw[0].secret);

      const authorized = await repo.findOneByOrFail({ id: saved.id });
      assert.equal(authorized.secret, plaintext);
    } finally {
      await source.destroy();
    }

    const wrongSource = new DataSource({
      type: 'postgres',
      url: databaseUrl,
      entities: [recordSchema],
      subscribers: [createTypeOrmSubscriber(unrestricted({
        key: wrongKey,
        entities: { GuardTypeOrmRecord: ['secret'] }
      }) as any)],
      synchronize: false
    });
    await wrongSource.initialize();
    try {
      await assert.rejects(
        wrongSource.getRepository('GuardTypeOrmRecord').findOneByOrFail({ id: 1 }),
        /decrypt|authentication|Unsupported state/i
      );
    } finally {
      await wrongSource.destroy();
    }
  });
});