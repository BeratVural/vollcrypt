'use strict';

const fs = require('node:fs');

const DEFAULT_MAX_THROUGHPUT_DROP_PERCENT = 20;
const COMPARABILITY_FIELDS = ['profile', 'backend', 'chunkSize', 'workers'];

function readResult(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function requirePositiveNumber(result, field, label) {
  const value = result[field];
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${label}.${field} must be a positive finite number`);
  }
  return value;
}

function compareBenchmarkResults(
  baseline,
  candidate,
  maxThroughputDropPercent = DEFAULT_MAX_THROUGHPUT_DROP_PERCENT,
) {
  if (
    typeof maxThroughputDropPercent !== 'number' ||
    !Number.isFinite(maxThroughputDropPercent) ||
    maxThroughputDropPercent < 0 ||
    maxThroughputDropPercent >= 100
  ) {
    throw new Error('maxThroughputDropPercent must be between 0 and 100');
  }

  for (const field of COMPARABILITY_FIELDS) {
    if (baseline[field] !== candidate[field]) {
      throw new Error(
        `benchmark results are not comparable: ${field} changed from ${baseline[field]} to ${candidate[field]}`,
      );
    }
  }

  const baselineThroughput = requirePositiveNumber(baseline, 'throughputGBs', 'baseline');
  const candidateThroughput = requirePositiveNumber(candidate, 'throughputGBs', 'candidate');
  const throughputDropPercent =
    ((baselineThroughput - candidateThroughput) / baselineThroughput) * 100;

  return {
    baselineThroughput,
    candidateThroughput,
    throughputDropPercent,
    maxThroughputDropPercent,
    regressed: throughputDropPercent > maxThroughputDropPercent,
  };
}

function main(argv) {
  const [baselinePath, candidatePath, thresholdText] = argv;
  if (!baselinePath || !candidatePath || argv.length > 3) {
    throw new Error(
      'usage: node check-regression.js <baseline.json> <candidate.json> [max-throughput-drop-percent]',
    );
  }

  const threshold =
    thresholdText === undefined
      ? DEFAULT_MAX_THROUGHPUT_DROP_PERCENT
      : Number(thresholdText);
  const comparison = compareBenchmarkResults(
    readResult(baselinePath),
    readResult(candidatePath),
    threshold,
  );
  const drop = comparison.throughputDropPercent.toFixed(2);
  console.log(
    `Throughput: ${comparison.baselineThroughput.toFixed(2)} -> ${comparison.candidateThroughput.toFixed(2)} GB/s (${drop}% drop; limit ${comparison.maxThroughputDropPercent}%).`,
  );
  if (comparison.regressed) {
    throw new Error('benchmark throughput regression exceeded the configured limit');
  }
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

module.exports = {
  compareBenchmarkResults,
  DEFAULT_MAX_THROUGHPUT_DROP_PERCENT,
};