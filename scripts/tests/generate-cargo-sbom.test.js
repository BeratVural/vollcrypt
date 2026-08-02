'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..', '..');

test('generates an actions/attest-compatible CycloneDX SBOM', () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vollcrypt-sbom-'));
  const outputPath = path.join(outputDir, 'sbom.cdx.json');

  try {
    execFileSync(
      process.execPath,
      [
        path.join(repoRoot, 'scripts', 'generate-cargo-sbom.js'),
        'vollcrypt-files/node/Cargo.toml',
        'vollcrypt-files/node/package.json',
        outputPath,
      ],
      { cwd: repoRoot, stdio: 'pipe' }
    );

    const sbom = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.equal(sbom.specVersion, '1.5');
    assert.match(
      sbom.serialNumber,
      /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    assert.equal(sbom.metadata.component.name, '@vollcrypt/files-node');
  } finally {
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
});