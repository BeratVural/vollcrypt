'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const [manifestPathArg, packageJsonPathArg, outputPathArg] = process.argv.slice(2);
if (!manifestPathArg || !packageJsonPathArg || !outputPathArg) {
  throw new Error(
    'Usage: node scripts/generate-cargo-sbom.js <Cargo.toml> <package.json> <output.json>'
  );
}

const manifestPath = path.resolve(manifestPathArg);
const packageJsonPath = path.resolve(packageJsonPathArg);
const outputPath = path.resolve(outputPathArg);
const npmPackage = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

const metadata = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--locked'], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
);

if (!metadata.resolve) {
  throw new Error('cargo metadata did not return a dependency graph');
}

const rootCargoPackage = metadata.packages.find(
  (pkg) => path.resolve(pkg.manifest_path) === manifestPath
);
if (!rootCargoPackage) {
  throw new Error(`Cargo package not found for manifest: ${manifestPathArg}`);
}

const packageById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
const nodeById = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));

function productionDependencyIds(node) {
  if (!node) return [];
  return node.deps
    .filter((dep) => dep.dep_kinds.some((kind) => kind.kind !== 'dev'))
    .map((dep) => dep.pkg);
}

const reachable = new Set();
const queue = [rootCargoPackage.id];
while (queue.length > 0) {
  const id = queue.shift();
  if (reachable.has(id)) continue;
  reachable.add(id);
  for (const dependencyId of productionDependencyIds(nodeById.get(id))) {
    queue.push(dependencyId);
  }
}

function cargoRef(pkg) {
  return `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`;
}

function npmRef(name, version) {
  const encodedName = name.startsWith('@')
    ? `${encodeURIComponent(name.split('/')[0])}/${encodeURIComponent(name.split('/')[1])}`
    : encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

function cargoComponent(pkg) {
  const component = {
    type: 'library',
    'bom-ref': cargoRef(pkg),
    name: pkg.name,
    version: pkg.version,
    purl: cargoRef(pkg),
  };
  if (pkg.license) {
    component.licenses = [{ expression: pkg.license }];
  }
  return component;
}

const cargoPackages = [...reachable]
  .map((id) => packageById.get(id))
  .filter(Boolean)
  .sort((a, b) => cargoRef(a).localeCompare(cargoRef(b)));

const npmBomRef = npmRef(npmPackage.name, npmPackage.version);
const dependencies = [
  {
    ref: npmBomRef,
    dependsOn: [cargoRef(rootCargoPackage)],
  },
  ...cargoPackages.map((pkg) => ({
    ref: cargoRef(pkg),
    dependsOn: productionDependencyIds(nodeById.get(pkg.id))
      .filter((id) => reachable.has(id))
      .map((id) => cargoRef(packageById.get(id)))
      .sort(),
  })),
];

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    component: {
      type: 'library',
      'bom-ref': npmBomRef,
      group: npmPackage.name.startsWith('@') ? npmPackage.name.split('/')[0] : undefined,
      name: npmPackage.name,
      version: npmPackage.version,
      purl: npmBomRef,
    },
  },
  components: cargoPackages.map(cargoComponent),
  dependencies,
};

if (sbom.metadata.component.group === undefined) {
  delete sbom.metadata.component.group;
}

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2) + '\n', 'utf8');
console.log(
  `Wrote CycloneDX SBOM with ${cargoPackages.length} Cargo components to ${outputPathArg}`
);
