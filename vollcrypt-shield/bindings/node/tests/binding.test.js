'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const shield = require('..')

test('loader accepts bundled binaries only', () => {
  const loader = fs.readFileSync(path.join(__dirname, '..', 'loader.js'), 'utf8')
  assert.equal(loader.includes("require('@vollcrypt/"), false)
})

test('ML-DSA signatures reject modified payloads', () => {
  const pair = shield.generateKeyPair()
  const payload = Buffer.from('approved')
  const signature = shield.sign(payload, pair.secretSeed)
  assert.equal(shield.verify(payload, pair.publicKey, signature), true)
  assert.equal(shield.verify(Buffer.from('modified'), pair.publicKey, signature), false)
})

test('signed snapshots are canonical and independently verifiable', () => {
  const pair = shield.generateKeyPair()
  const entries = [
    {
      path: 'config/app.toml',
      kind: 'file',
      contentDigest: Buffer.alloc(32, 1),
      metadataDigest: Buffer.alloc(32, 2),
      size: 12
    }
  ]
  const encoded = shield.createSignedSnapshot('node-test', entries, 42, pair.secretSeed)
  const summary = shield.verifySignedSnapshot(encoded)
  assert.equal(summary.scopeId, 'node-test')
  assert.equal(summary.entryCount, 1)
  assert.equal(summary.root.length, 32)
})
