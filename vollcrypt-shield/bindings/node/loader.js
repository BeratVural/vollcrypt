'use strict'

const { existsSync } = require('node:fs')
const { join } = require('node:path')

function linuxLibc() {
  const report = process.report && process.report.getReport()
  return report && report.header && report.header.glibcVersionRuntime ? 'gnu' : 'musl'
}

function binaryCandidates() {
  const { platform, arch } = process
  if (platform === 'win32' && ['x64', 'ia32', 'arm64'].includes(arch)) {
    return [`vollcrypt-shield-core-node.win32-${arch}-msvc.node`]
  }
  if (platform === 'darwin' && ['x64', 'arm64'].includes(arch)) {
    return [
      'vollcrypt-shield-core-node.darwin-universal.node',
      `vollcrypt-shield-core-node.darwin-${arch}.node`,
    ]
  }
  if (platform === 'freebsd' && arch === 'x64') {
    return ['vollcrypt-shield-core-node.freebsd-x64.node']
  }
  if (platform === 'android' && arch === 'arm64') {
    return ['vollcrypt-shield-core-node.android-arm64.node']
  }
  if (platform === 'android' && arch === 'arm') {
    return ['vollcrypt-shield-core-node.android-arm-eabi.node']
  }
  if (platform === 'linux') {
    const libc = linuxLibc()
    if (arch === 'arm') {
      const abi = libc === 'musl' ? 'musleabihf' : 'gnueabihf'
      return [`vollcrypt-shield-core-node.linux-arm-${abi}.node`]
    }
    if (['x64', 'arm64', 'riscv64'].includes(arch)) {
      return [`vollcrypt-shield-core-node.linux-${arch}-${libc}.node`]
    }
    if (arch === 's390x' && libc === 'gnu') {
      return ['vollcrypt-shield-core-node.linux-s390x-gnu.node']
    }
  }
  return []
}

const candidates = binaryCandidates()
const binary = candidates.find((name) => existsSync(join(__dirname, name)))
if (!binary) {
  throw new Error(
    `No bundled Vollcrypt Shield binary for ${process.platform}/${process.arch}; expected one of: ${candidates.join(', ') || 'none'}`,
  )
}

module.exports = require(join(__dirname, binary))
