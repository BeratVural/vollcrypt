"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbGuardContractError = exports.SUPPORTED_KEY_VERSIONS = exports.DB_GUARD_CONTRACT_VERSION = void 0;
exports.validateDbGuardContract = validateDbGuardContract;
exports.toPrismaDbGuardOptions = toPrismaDbGuardOptions;
exports.toMongooseDbGuardOptions = toMongooseDbGuardOptions;
exports.toDrizzleDbGuardOptions = toDrizzleDbGuardOptions;
exports.toTypeOrmDbGuardOptions = toTypeOrmDbGuardOptions;
exports.DB_GUARD_CONTRACT_VERSION = 1;
exports.SUPPORTED_KEY_VERSIONS = ['1', '2'];
class DbGuardContractError extends Error {
    code;
    constructor(code, message) {
        super(`Vollcrypt DbGuard contract [${code}]: ${message}`);
        this.code = code;
        this.name = 'DbGuardContractError';
    }
}
exports.DbGuardContractError = DbGuardContractError;
function keyVersions(keys) {
    return Buffer.isBuffer(keys) ? ['1'] : Object.keys(keys);
}
function validateResourceMap(resources, label) {
    const entries = Object.entries(resources);
    if (entries.length === 0) {
        throw new DbGuardContractError('INVALID_RESOURCE_SCOPE', `${label} must not be empty.`);
    }
    for (const [resource, fields] of entries) {
        if (!resource.trim() || !Array.isArray(fields) || fields.length === 0) {
            throw new DbGuardContractError('INVALID_RESOURCE_SCOPE', `${label}.${resource || '<empty>'} must contain at least one field.`);
        }
        if (fields.some((field) => typeof field !== 'string' || !field.trim())) {
            throw new DbGuardContractError('INVALID_RESOURCE_SCOPE', `${label}.${resource} contains an invalid field name.`);
        }
    }
}
function validateDbGuardContract(contract) {
    if (contract.contractVersion !== exports.DB_GUARD_CONTRACT_VERSION) {
        throw new DbGuardContractError('UNSUPPORTED_CONTRACT_VERSION', `expected ${exports.DB_GUARD_CONTRACT_VERSION}, got ${String(contract.contractVersion)}.`);
    }
    const versions = keyVersions(contract.keyring.keys);
    if (versions.length === 0 || versions.some((version) => !exports.SUPPORTED_KEY_VERSIONS.includes(version))) {
        throw new DbGuardContractError('INVALID_KEYRING', `key versions must be one or more of ${exports.SUPPORTED_KEY_VERSIONS.join(', ')}.`);
    }
    for (const version of versions) {
        const key = Buffer.isBuffer(contract.keyring.keys)
            ? contract.keyring.keys
            : contract.keyring.keys[version];
        if (!Buffer.isBuffer(key) || key.length !== 32) {
            throw new DbGuardContractError('INVALID_KEYRING', `key version ${version} must be 32 bytes.`);
        }
    }
    const activeVersion = contract.keyring.activeVersion || versions[0];
    if (!versions.includes(activeVersion)) {
        throw new DbGuardContractError('INVALID_KEYRING', `active key version ${activeVersion} is not present in the keyring.`);
    }
    validateResourceMap(contract.resources, 'resources');
    if (contract.blindIndexes) {
        validateResourceMap(contract.blindIndexes.resources, 'blindIndexes.resources');
    }
}
function securityOptions(contract) {
    return contract.security ? { ...contract.security } : {};
}
function toPrismaDbGuardOptions(contract) {
    validateDbGuardContract(contract);
    return {
        key: contract.keyring.keys,
        activeKeyVersion: contract.keyring.activeVersion,
        models: contract.resources,
        blindIndexes: contract.blindIndexes
            ? {
                rootSalt: contract.blindIndexes.rootSalt,
                allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
                models: contract.blindIndexes.resources
            }
            : undefined,
        ...securityOptions(contract)
    };
}
function toMongooseDbGuardOptions(contract, resource) {
    validateDbGuardContract(contract);
    const fields = contract.resources[resource];
    if (!fields) {
        throw new DbGuardContractError('RESOURCE_NOT_FOUND', `resource ${resource} is not configured.`);
    }
    return {
        key: contract.keyring.keys,
        activeKeyVersion: contract.keyring.activeVersion,
        fields,
        blindIndexes: contract.blindIndexes
            ? {
                rootSalt: contract.blindIndexes.rootSalt,
                allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
                fields: contract.blindIndexes.resources[resource] || [],
                modelName: resource
            }
            : undefined,
        ...securityOptions(contract)
    };
}
function toDrizzleDbGuardOptions(contract) {
    validateDbGuardContract(contract);
    return {
        key: contract.keyring.keys,
        activeKeyVersion: contract.keyring.activeVersion,
        blindIndexes: contract.blindIndexes
            ? {
                rootSalt: contract.blindIndexes.rootSalt,
                allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage
            }
            : undefined,
        ...securityOptions(contract)
    };
}
function toTypeOrmDbGuardOptions(contract) {
    validateDbGuardContract(contract);
    return {
        key: contract.keyring.keys,
        activeKeyVersion: contract.keyring.activeVersion,
        entities: contract.resources,
        blindIndexes: contract.blindIndexes
            ? {
                rootSalt: contract.blindIndexes.rootSalt,
                allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
                entities: contract.blindIndexes.resources
            }
            : undefined,
        ...securityOptions(contract)
    };
}
