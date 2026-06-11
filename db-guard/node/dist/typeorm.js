"use strict";
var __esDecorate = (this && this.__esDecorate) || function (ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
    function accept(f) { if (f !== void 0 && typeof f !== "function") throw new TypeError("Function expected"); return f; }
    var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
    var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
    var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
    var _, done = false;
    for (var i = decorators.length - 1; i >= 0; i--) {
        var context = {};
        for (var p in contextIn) context[p] = p === "access" ? {} : contextIn[p];
        for (var p in contextIn.access) context.access[p] = contextIn.access[p];
        context.addInitializer = function (f) { if (done) throw new TypeError("Cannot add initializers after decoration has completed"); extraInitializers.push(accept(f || null)); };
        var result = (0, decorators[i])(kind === "accessor" ? { get: descriptor.get, set: descriptor.set } : descriptor[key], context);
        if (kind === "accessor") {
            if (result === void 0) continue;
            if (result === null || typeof result !== "object") throw new TypeError("Object expected");
            if (_ = accept(result.get)) descriptor.get = _;
            if (_ = accept(result.set)) descriptor.set = _;
            if (_ = accept(result.init)) initializers.unshift(_);
        }
        else if (_ = accept(result)) {
            if (kind === "field") initializers.unshift(_);
            else descriptor[key] = _;
        }
    }
    if (target) Object.defineProperty(target, contextIn.name, descriptor);
    done = true;
};
var __runInitializers = (this && this.__runInitializers) || function (thisArg, initializers, value) {
    var useValue = arguments.length > 2;
    for (var i = 0; i < initializers.length; i++) {
        value = useValue ? initializers[i].call(thisArg, value) : initializers[i].call(thisArg);
    }
    return useValue ? value : void 0;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createTypeOrmSubscriber = createTypeOrmSubscriber;
const typeorm_1 = require("typeorm");
const prisma_1 = require("./prisma");
const blind_index_1 = require("./blind-index");
const security_1 = require("./security");
function getKeys(options) {
    let keys;
    let activeVersion;
    if (Buffer.isBuffer(options.key)) {
        keys = { '1': options.key };
        activeVersion = '1';
    }
    else {
        keys = options.key;
        activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
    }
    return { keys, activeVersion };
}
function createTypeOrmSubscriber(options) {
    const { keys, activeVersion } = getKeys(options);
    const activeKey = keys[activeVersion];
    if (!activeKey) {
        throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
    }
    (0, security_1.registerKeysForZeroization)(keys);
    let VollcryptDbGuardSubscriber = (() => {
        let _classDecorators = [(0, typeorm_1.EventSubscriber)()];
        let _classDescriptor;
        let _classExtraInitializers = [];
        let _classThis;
        var VollcryptDbGuardSubscriber = class {
            static { _classThis = this; }
            static {
                const _metadata = typeof Symbol === "function" && Symbol.metadata ? Object.create(null) : void 0;
                __esDecorate(null, _classDescriptor = { value: _classThis }, _classDecorators, { kind: "class", name: _classThis.name, metadata: _metadata }, null, _classExtraInitializers);
                VollcryptDbGuardSubscriber = _classThis = _classDescriptor.value;
                if (_metadata) Object.defineProperty(_classThis, Symbol.metadata, { enumerable: true, configurable: true, writable: true, value: _metadata });
                __runInitializers(_classThis, _classExtraInitializers);
            }
            listenTo() {
                return Object;
            }
            beforeInsert(event) {
                const entityName = event.metadata.name;
                const fields = options.entities[entityName];
                if (fields && event.entity) {
                    // Calculate blind indexes first (before the original field gets encrypted)
                    if (options.blindIndexes && options.blindIndexes.rootSalt) {
                        const bidxFields = options.blindIndexes.entities[entityName];
                        if (bidxFields) {
                            for (const field of bidxFields) {
                                if (event.entity[field] !== undefined && event.entity[field] !== null) {
                                    const bidxField = `${field}_bidx`;
                                    event.entity[bidxField] = (0, blind_index_1.computeBlindIndex)(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`);
                                }
                            }
                        }
                    }
                    // Encrypt fields
                    for (const field of fields) {
                        if (event.entity[field] !== undefined && event.entity[field] !== null) {
                            event.entity[field] = (0, prisma_1.encryptValue)(event.entity[field], activeKey, activeVersion);
                        }
                    }
                }
            }
            beforeUpdate(event) {
                const entityName = event.metadata.name;
                const fields = options.entities[entityName];
                if (fields && event.entity) {
                    // Calculate blind indexes first
                    if (options.blindIndexes && options.blindIndexes.rootSalt) {
                        const bidxFields = options.blindIndexes.entities[entityName];
                        if (bidxFields) {
                            for (const field of bidxFields) {
                                if (event.entity[field] !== undefined && event.entity[field] !== null) {
                                    const bidxField = `${field}_bidx`;
                                    event.entity[bidxField] = (0, blind_index_1.computeBlindIndex)(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`);
                                }
                            }
                        }
                    }
                    // Encrypt fields
                    for (const field of fields) {
                        if (event.entity[field] !== undefined && event.entity[field] !== null) {
                            event.entity[field] = (0, prisma_1.encryptValue)(event.entity[field], activeKey, activeVersion);
                        }
                    }
                }
            }
            afterLoad(entity, event) {
                if (!event || !event.metadata)
                    return;
                const entityName = event.metadata.name;
                const fields = options.entities[entityName];
                if (fields && entity) {
                    for (const field of fields) {
                        if (entity[field] !== undefined && entity[field] !== null) {
                            try {
                                entity[field] = (0, security_1.decryptWithSecurity)(entity[field], (val) => (0, prisma_1.decryptValue)(val, keys), entityName, field, entity.id || entity._id, options);
                            }
                            catch (err) {
                                throw new Error(`TypeORM db-guard failed to decrypt field "${field}": ${err.message}`);
                            }
                        }
                    }
                }
            }
        };
        return VollcryptDbGuardSubscriber = _classThis;
    })();
    return VollcryptDbGuardSubscriber;
}
