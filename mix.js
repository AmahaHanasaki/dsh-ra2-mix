/**
 * RA2 MIX archive codec.
 *
 * Reads Red Alert 2 / Yuri's Revenge MIX archives (the format XCC Mixer reads):
 *   - plain new-format mixes: flags(u32) + count(u16) + bodySize(u32) + 12-byte index entries
 *   - encrypted mixes (flags & 0x20000): 80-byte RSA-wrapped Blowfish key + Blowfish-ECB header
 *   - file IDs are CRC32 (zlib) of the upper-cased, block-padded file name
 *
 * References (public format documentation):
 *   - XCC Utilities MIX format docs (Olaf van der Spek)
 *   - https://docs.rs/ra2-mix (MPL-2.0) and https://docs.rs/cnc-formats (MIT/Apache-2.0)
 */
import { readFileSync } from 'node:fs'

// ---- pi hex digits via the BBP formula (needed for Blowfish constants) ----
function piHexAt(p) {
  const frac = (m) => {
    let sum = 0
    for (let k = 0; k <= p; k++) {
      const den = 8 * k + m
      let pow = 1n, base = 16n, exp = BigInt(p - k), mod = BigInt(den)
      while (exp > 0n) {
        if (exp & 1n) pow = (pow * base) % mod
        base = (base * base) % mod
        exp >>= 1n
      }
      sum += Number(pow) / den
      sum -= Math.floor(sum)
    }
    let tail = 0, pow16 = 1 / 16
    for (let k = p + 1; k <= p + 40; k++) {
      tail += pow16 / (8 * k + m)
      pow16 /= 16
    }
    return sum + tail
  }
  const x = 4 * frac(1) - 2 * frac(4) - frac(5) - frac(6)
  const f = x - Math.floor(x)
  return Math.floor(16 * f)
}

let PI_HEX = null
function piHexDigits(count) {
  if (PI_HEX !== null && PI_HEX.length >= count) return PI_HEX.slice(0, count)
  const hex = []
  for (let p = 0; p < count; p++) hex.push(piHexAt(p).toString(16))
  PI_HEX = hex.join('')
  return PI_HEX
}

// ---- Blowfish (standard, big-endian words) ----
export function blowfishKeyed(keyBytes) {
  const hex = piHexDigits(8336)
  const P = new Uint32Array(18)
  const S = new Uint32Array(1024)
  let pos = 0
  for (let i = 0; i < 18; i++) {
    P[i] = parseInt(hex.slice(pos, pos + 8), 16) >>> 0
    pos += 8
  }
  for (let i = 0; i < 1024; i++) {
    S[i] = parseInt(hex.slice(pos, pos + 8), 16) >>> 0
    pos += 8
  }
  const F = (x) => {
    const a = (S[(x >>> 24) & 0xff] + S[0x100 + ((x >>> 16) & 0xff)]) >>> 0
    const b = (a ^ S[0x200 + ((x >>> 8) & 0xff)]) >>> 0
    return (b + S[0x300 + (x & 0xff)]) >>> 0
  }
  const enc = (L, R) => {
    for (let i = 0; i < 16; i++) {
      L = (L ^ P[i]) >>> 0
      R = (F(L) ^ R) >>> 0
      const t = L; L = R; R = t
    }
    const t = L; L = R; R = t
    R = (R ^ P[16]) >>> 0
    L = (L ^ P[17]) >>> 0
    return [L >>> 0, R >>> 0]
  }
  let k = 0
  for (let i = 0; i < 18; i++) {
    let w = 0
    for (let j = 0; j < 4; j++) w = ((w << 8) | keyBytes[k++ % keyBytes.length]) >>> 0
    P[i] = (P[i] ^ w) >>> 0
  }
  let L = 0, R = 0
  for (let i = 0; i < 18; i += 2) {
    const r = enc(L, R)
    L = r[0]; R = r[1]
    P[i] = L; P[i + 1] = R
  }
  for (let i = 0; i < 1024; i += 2) {
    const r = enc(L, R)
    L = r[0]; R = r[1]
    S[i] = L; S[i + 1] = R
  }
  const decryptBlockBytes = (block8) => {
    let L = block8.readUInt32BE(0) >>> 0
    let R = block8.readUInt32BE(4) >>> 0
    L = (L ^ P[17]) >>> 0
    R = (R ^ P[16]) >>> 0
    const t = L; L = R; R = t
    for (let i = 15; i >= 0; i--) {
      const B = R
      const nl = (B ^ P[i]) >>> 0
      const nr = (L ^ F(B)) >>> 0
      L = nl
      R = nr
    }
    const out = Buffer.alloc(8)
    out.writeUInt32BE(L, 0)
    out.writeUInt32BE(R, 4)
    return out
  }
  return { decryptBlockBytes, enc }
}

// ---- RSA-wrapped Blowfish key (Westwood public key) ----
const PUBKEY_B64 = 'AihRvNoIbTn85FZRYNZRcT+i6KpU+maCsEqr3Q5q+LDB5tH7Tz2qQ38V'
const PUBKEY_DER = Buffer.from(PUBKEY_B64, 'base64')
const MODULUS = BigInt('0x' + PUBKEY_DER.slice(2).toString('hex'))
const EXPONENT = 65537n
const RSA_CHUNK = Math.floor((MODULUS.toString(2).length - 1) / 8) + 1

function deriveBlowfishKey(keySource80) {
  const out = []
  for (let off = 0; off < 80; off += RSA_CHUNK) {
    const chunk = keySource80.subarray(off, off + RSA_CHUNK)
    let c = 0n
    for (let i = chunk.length - 1; i >= 0; i--) c = (c << 8n) | BigInt(chunk[i])
    let r = 1n, base = c, exp = EXPONENT, mod = MODULUS
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % mod
      base = (base * base) % mod
      exp >>= 1n
    }
    const rb = r.toString(16).padStart((RSA_CHUNK - 1) * 2, '0')
    const bytes = Buffer.from(rb.slice(-(RSA_CHUNK - 1) * 2), 'hex').reverse()
    for (const b of bytes) out.push(b)
  }
  return Buffer.from(out.slice(0, 56))
}

// ---- RA2 file name hash (CRC32 of obfuscated upper-case name) ----
function crc32(buf) {
  let crc = 0xFFFFFFFF
  for (const byte of buf) {
    crc ^= byte
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xEDB88320 : 0)
  }
  return (crc ^ 0xFFFFFFFF) >>> 0
}

export function ra2Crc(filename) {
  let name = filename.toUpperCase()
  const len = name.length
  const salt = len & ~3
  if (len & 3) {
    name += String.fromCharCode(len - salt)
    for (let i = 0; i < 3 - (len & 3); i++) name += name[salt]
  }
  return crc32(Buffer.from(name, 'latin1'))
}

// ---- MIX parsing ----
export const MIX_FLAG_ENCRYPTED = 0x20000

export function parseMixFile(file) {
  const buf = readFileSync(file)
  return parseMix(buf, file)
}

export function parseMix(buf) {
  const flags = buf.readUInt32LE(0) >>> 0
  let count, dataSize, entries, bodyStart, encrypted = false, blowfishKey = null
  if (flags & MIX_FLAG_ENCRYPTED) {
    encrypted = true
    blowfishKey = deriveBlowfishKey(buf.subarray(4, 84))
    const bf = blowfishKeyed(blowfishKey)
    const encStart = 84
    const first = bf.decryptBlockBytes(buf.subarray(encStart, encStart + 8))
    count = first.readUInt16LE(0)
    dataSize = first.readUInt32LE(2) >>> 0
    const total = 6 + 12 * count
    const blocks = Math.ceil(total / 8)
    if (encStart + blocks * 8 > buf.length) throw new Error('corrupt MIX: encrypted index overruns file')
    const plain = Buffer.alloc(blocks * 8)
    for (let i = 0; i < blocks; i++) {
      bf.decryptBlockBytes(buf.subarray(encStart + i * 8, encStart + (i + 1) * 8)).copy(plain, i * 8)
    }
    entries = []
    for (let i = 0; i < count; i++) {
      entries.push({
        id: plain.readUInt32LE(6 + i * 12) >>> 0,
        offset: plain.readInt32LE(6 + i * 12 + 4),
        size: plain.readInt32LE(6 + i * 12 + 8),
        stub: plain.readInt32LE(6 + i * 12 + 4) < 0 || plain.readInt32LE(6 + i * 12 + 8) < 0,
      })
    }
    bodyStart = encStart + blocks * 8
  } else {
    count = buf.readUInt16LE(4)
    dataSize = buf.readUInt32LE(6) >>> 0
    entries = []
    if (10 + 12 * count > buf.length) throw new Error('corrupt MIX: index overruns file')
    for (let i = 0; i < count; i++) {
      entries.push({
        id: buf.readUInt32LE(10 + i * 12) >>> 0,
        offset: buf.readInt32LE(10 + i * 12 + 4),
        size: buf.readInt32LE(10 + i * 12 + 8),
        stub: buf.readInt32LE(10 + i * 12 + 4) < 0 || buf.readInt32LE(10 + i * 12 + 8) < 0,
      })
    }
    bodyStart = 10 + 12 * count
  }
  return { flags, encrypted, count, dataSize, entries, bodyStart, blowfishKey, fileSize: buf.length }
}

/** Read one entry's data. Verified against real RA2 mixes: only the header
 *  and index are Blowfish-encrypted; file data is stored in plaintext. */
export function readEntryData(buf, mix, entry) {
  const body = buf.subarray(mix.bodyStart)
  const start = entry.offset
  const end = start + entry.size
  if (start < 0 || entry.size < 0) throw new Error(`entry is a stub (offset=${entry.offset}, size=${entry.size})`)
  if (end > body.length) throw new Error(`entry range [${start}, ${end}) out of bounds (body ${body.length} bytes)`)
  return Buffer.from(body.subarray(start, end))
}
