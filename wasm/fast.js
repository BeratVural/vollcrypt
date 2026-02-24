import init, * as wasm from "./pkg/wasm.js"

function getSubtle() {
  const cryptoObj = globalThis?.crypto
  return cryptoObj && cryptoObj.subtle ? cryptoObj.subtle : null
}

function normalizeU8(data) {
  if (data == null) return null
  return data instanceof Uint8Array ? data : new Uint8Array(data)
}

async function importAesKey(key, usages) {
  if (typeof CryptoKey !== "undefined" && key instanceof CryptoKey) {
    return key
  }
  const subtle = getSubtle()
  if (!subtle) {
    throw new Error("WebCrypto not available")
  }
  const raw = normalizeU8(key)
  if (!raw) {
    throw new Error("Invalid key")
  }
  return await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages)
}

export async function encryptAesGcmWeb(key, plaintext, aad) {
  const subtle = getSubtle()
  if (!subtle) {
    throw new Error("WebCrypto not available")
  }
  const pt = normalizeU8(plaintext)
  if (!pt) {
    throw new Error("Invalid plaintext")
  }
  const aadU8 = normalizeU8(aad)
  const cryptoKey = await importAesKey(key, ["encrypt"])
  const iv = new Uint8Array(12)
  globalThis.crypto.getRandomValues(iv)
  const algo = { name: "AES-GCM", iv }
  if (aadU8 && aadU8.length > 0) {
    algo.additionalData = aadU8
  }
  const ct = await subtle.encrypt(algo, cryptoKey, pt)
  const out = new Uint8Array(iv.length + ct.byteLength)
  out.set(iv, 0)
  out.set(new Uint8Array(ct), iv.length)
  return out
}

export async function decryptAesGcmWeb(key, ciphertext, aad) {
  const subtle = getSubtle()
  if (!subtle) {
    throw new Error("WebCrypto not available")
  }
  const ct = normalizeU8(ciphertext)
  if (!ct || ct.length < 12) {
    throw new Error("Ciphertext too short")
  }
  const aadU8 = normalizeU8(aad)
  const cryptoKey = await importAesKey(key, ["decrypt"])
  const iv = ct.slice(0, 12)
  const data = ct.slice(12)
  const algo = { name: "AES-GCM", iv }
  if (aadU8 && aadU8.length > 0) {
    algo.additionalData = aadU8
  }
  const pt = await subtle.decrypt(algo, cryptoKey, data)
  return new Uint8Array(pt)
}

export async function encryptAesGcmAuto(key, plaintext, aad) {
  const subtle = getSubtle()
  if (subtle) {
    return await encryptAesGcmWeb(key, plaintext, aad)
  }
  return wasm.encryptAesGcm(key, plaintext, aad ?? null)
}

export async function decryptAesGcmAuto(key, ciphertext, aad) {
  const subtle = getSubtle()
  if (subtle) {
    return await decryptAesGcmWeb(key, ciphertext, aad)
  }
  return wasm.decryptAesGcm(key, ciphertext, aad ?? null)
}

function buildChunkAad(baseAad, chunkIndex) {
  const aadPrefix = baseAad ? normalizeU8(baseAad) : null
  const indexBuf = new Uint8Array(4)
  const view = new DataView(indexBuf.buffer)
  view.setUint32(0, chunkIndex, false)
  if (!aadPrefix || aadPrefix.length === 0) {
    return indexBuf
  }
  const out = new Uint8Array(aadPrefix.length + 4)
  out.set(aadPrefix, 0)
  out.set(indexBuf, aadPrefix.length)
  return out
}

export async function encryptAesGcmChunkedWeb(key, plaintext, aad, chunkSize) {
  if (!chunkSize || chunkSize <= 0) {
    throw new Error("Invalid chunk size")
  }
  const pt = normalizeU8(plaintext)
  if (!pt) {
    throw new Error("Invalid plaintext")
  }
  const totalLen = pt.length
  const chunkCount = totalLen === 0 ? 1 : Math.ceil(totalLen / chunkSize)
  if (chunkCount > 0xffffffff) {
    throw new Error("Chunk count exceeds supported maximum")
  }
  const parts = []
  const header = new Uint8Array(4)
  new DataView(header.buffer).setUint32(0, chunkCount, false)
  parts.push(header)
  for (let i = 0; i < chunkCount; i += 1) {
    const start = i * chunkSize
    const end = totalLen === 0 ? 0 : Math.min(start + chunkSize, totalLen)
    const chunk = pt.subarray(start, end)
    const aadChunk = buildChunkAad(aad, i)
    const enc = await encryptAesGcmWeb(key, chunk, aadChunk)
    const h = new Uint8Array(8)
    const v = new DataView(h.buffer)
    v.setUint32(0, i, false)
    v.setUint32(4, enc.length, false)
    parts.push(h, enc)
    if (totalLen === 0) break
  }
  const total = parts.reduce((sum, p) => sum + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export async function decryptAesGcmChunkedWeb(key, ciphertext, aad) {
  const ct = normalizeU8(ciphertext)
  if (!ct || ct.length < 4) {
    throw new Error("Encrypted data too short")
  }
  const view = new DataView(ct.buffer, ct.byteOffset, ct.byteLength)
  const chunkCount = view.getUint32(0, false)
  if (chunkCount === 0) {
    throw new Error("Invalid chunk count")
  }
  let offset = 4
  const parts = []
  for (let expected = 0; expected < chunkCount; expected += 1) {
    if (offset + 8 > ct.length) {
      throw new Error("Encrypted data truncated")
    }
    const chunkIndex = view.getUint32(offset, false)
    const chunkLen = view.getUint32(offset + 4, false)
    offset += 8
    if (chunkIndex !== expected) {
      throw new Error("Chunk index mismatch")
    }
    if (chunkLen === 0 || offset + chunkLen > ct.length) {
      throw new Error("Invalid chunk length")
    }
    const chunk = ct.subarray(offset, offset + chunkLen)
    const aadChunk = buildChunkAad(aad, chunkIndex)
    const dec = await decryptAesGcmWeb(key, chunk, aadChunk)
    parts.push(dec)
    offset += chunkLen
  }
  if (offset !== ct.length) {
    throw new Error("Trailing data after chunks")
  }
  const total = parts.reduce((sum, p) => sum + p.length, 0)
  const out = new Uint8Array(total)
  let outOffset = 0
  for (const p of parts) {
    out.set(p, outOffset)
    outOffset += p.length
  }
  return out
}

export async function encryptAesGcmChunkedAuto(key, plaintext, aad, chunkSize) {
  const subtle = getSubtle()
  if (subtle) {
    return await encryptAesGcmChunkedWeb(key, plaintext, aad, chunkSize)
  }
  return wasm.encryptAesGcmChunked(key, plaintext, aad ?? null, chunkSize)
}

export async function decryptAesGcmChunkedAuto(key, ciphertext, aad) {
  const subtle = getSubtle()
  if (subtle) {
    return await decryptAesGcmChunkedWeb(key, ciphertext, aad)
  }
  return wasm.decryptAesGcmChunked(key, ciphertext, aad ?? null)
}

export { init }
export * from "./pkg/wasm.js"
