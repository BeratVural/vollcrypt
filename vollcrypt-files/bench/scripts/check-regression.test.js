'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compareBenchmarkResults } = require('./check-regression.js');

function result(throughputGBs, overrides = {}) {
  return {
    profile: 'balanced',
    backend: 'AES-NI',
    chunkSize: 1048576,
    workers: 2,
    throughputGBs,
    ...overrides,
  };
}

test('accepts throughput inside the regression budget', () => {
  const comparison = compareBenchmarkResults(result(2), result(1.7), 20);
  assert.equal(comparison.regressed, false);
  assert.equal(Math.round(comparison.throughputDropPercent), 15);
});

test('rejects throughput outside the regression budget', () => {
  const comparison = compareBenchmarkResults(result(2), result(1.5), 20);
  assert.equal(comparison.regressed, true);
  assert.equal(Math.round(comparison.throughputDropPercent), 25);
});

test('rejects results produced with different benchmark settings', () => {
  assert.throws(
    () => compareBenchmarkResults(result(2), result(2, { workers: 4 })),
    /not comparable: workers changed/,
  );
});

test('rejects malformed throughput values', () => {
  assert.throws(
    () => compareBenchmarkResults(result(2), result(0)),
    /candidate\.throughputGBs must be a positive finite number/,
  );
});