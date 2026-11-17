/**
 * RA2 MIX archive tools.
 *
 * Reads and extracts Red Alert 2 / Yuri's Revenge MIX archives (the format
 * XCC Mixer reads), including encrypted archives (Blowfish header), and can
 * launch the XCC Mixer.exe GUI for interactive browsing.
 */
import { readFileSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { parseMix, readEntryData, ra2Crc } from './mix.js'

export const inject = ['tools']

const textRender = (_args, value) => [{ type: 'text', text: value }]

const MAX_EXTRACT_FILES = 200
const MAX_EXTRACT_BYTES = 512 * 1024 * 1024

function sanitizeName(name) {
  const base = name.replace(/\\/g, '/').split('/').pop()
  return base.replace(/[^A-Za-z0-9._-]/g, '_')
}

function parseId(value) {
  if (typeof value === 'number') return value >>> 0
  const s = String(value).trim()
  if (/^0x[0-9a-f]{1,8}$/i.test(s)) return parseInt(s.slice(2), 16) >>> 0
  if (/^[0-9]{1,10}$/.test(s)) return parseInt(s, 10) >>> 0
  throw new Error(`bad entry id: ${JSON.stringify(value)} (use 0x hex or decimal)`)
}

export function apply(ctx, config = {}) {
  const defaults = {
    mixerPath: typeof config.mixerPath === 'string' ? config.mixerPath : '',
    defaultMix: typeof config.defaultMix === 'string' ? config.defaultMix : '',
  }

  const resolveFile = (args) => {
    const file = typeof args.file === 'string' && args.file !== '' ? args.file : defaults.defaultMix
    if (!file) throw new Error('no file given and no defaultMix configured for this plugin')
    return file
  }

  ctx.effect(() => ctx.tools.register({
    name: 'mix_info',
    description: 'Read a Red Alert 2 MIX archive and return its header (flags, encryption state, entry count, body size) plus a paged entry list. Each entry shows its index, file ID (a CRC32 hash of the file name), offset, and size; stub entries (offset/size negative) and out-of-range entries are flagged. Use mix_hash to convert a file name into its ID, then match it against this list.',
    parameters: {
      file: { type: 'string', description: 'MIX file path; defaults to the configured defaultMix' },
      offset: { type: 'number', description: 'Skip this many entries first; default 0' },
      limit: { type: 'number', description: 'Entries per page, 1-500; default 50' },
    },
    output: { schema: { type: 'string' }, render: textRender },
    async execute(args) {
      const file = resolveFile(args)
      if (!existsSync(file)) throw new Error(`MIX file not found: ${file}`)
      const mix = parseMix(readFileSync(file))
      const limit = Math.min(500, Math.max(1, Math.trunc(args.limit ?? 50)))
      const offset = Math.max(0, Math.trunc(args.offset ?? 0))
      const page = mix.entries.slice(offset, offset + limit).map((e, i) => {
        const idx = offset + i
        let status = 'ok'
        if (e.stub) status = 'stub'
        else if (e.offset + e.size > mix.fileSize - mix.bodyStart) status = 'out-of-range'
        return { index: idx, id: `0x${e.id.toString(16).padStart(8, '0')}`, offset: e.offset, size: e.size, status }
      })
      return JSON.stringify({
        file,
        encrypted: mix.encrypted,
        flags: `0x${mix.flags.toString(16)}`,
        entries: mix.count,
        declaredBodySize: mix.dataSize,
        actualBodySize: mix.fileSize - mix.bodyStart,
        fileSize: mix.fileSize,
        shown: page,
        total: mix.count,
        truncated: offset + limit < mix.count,
        offset,
      }, null, 2)
    },
    presentCall: (args) => ({ card: 'generic', title: 'Read MIX archive', kind: 'read', rawInput: args }),
  }))

  ctx.effect(() => ctx.tools.register({
    name: 'mix_hash',
    description: 'Compute the MIX file ID for a file name: the CRC32 of the upper-cased name padded to a 4-character boundary (the RA2/TS MIX hash). Use it to find an entry inside a MIX archive, or together with mix_extract.',
    parameters: {
      names: { type: 'array', items: { type: 'string' }, description: 'File names, e.g. ["ra2md.csf", "rulesmo.ini"]' },
    },
    output: { schema: { type: 'string' }, render: textRender },
    async execute(args) {
      if (!Array.isArray(args.names) || args.names.length === 0) throw new Error('names array is required')
      const results = args.names.map((name) => {
        const id = ra2Crc(String(name))
        return { name: String(name), id: `0x${id.toString(16).padStart(8, '0')}`, idNumber: id }
      })
      return JSON.stringify({ results }, null, 2)
    },
    presentCall: (args) => ({ card: 'generic', title: 'Hash MIX file names', kind: 'read', rawInput: args }),
  }))

  ctx.effect(() => ctx.tools.register({
    name: 'mix_extract',
    description: 'Extract files from a RA2 MIX archive into a directory (created if missing). Select entries by exact file name (the ID hash is computed automatically), by 0-based entry index, or by file ID (0x hex or decimal). Both plain and Blowfish-encrypted archives are handled; file data is stored in plaintext inside MIX archives. At most 200 files and 512 MiB per call. Returns what was written and what was not found.',
    parameters: {
      file: { type: 'string', description: 'MIX file path; defaults to the configured defaultMix' },
      outDir: { type: 'string', required: true, description: 'Directory to write extracted files into' },
      names: { type: 'array', items: { type: 'string' }, description: 'Extract entries whose name hashes to a matching ID (first and any duplicate matches)' },
      indexes: { type: 'array', items: { type: 'number' }, description: 'Extract entries by 0-based index from mix_info' },
      ids: { type: 'array', items: { type: 'string' }, description: 'Extract entries by file ID, 0x hex or decimal' },
    },
    output: { schema: { type: 'string' }, render: textRender },
    async execute(args) {
      const file = resolveFile(args)
      const outDir = typeof args.outDir === 'string' && args.outDir !== '' ? args.outDir : null
      if (!outDir) throw new Error('outDir is required')
      if (!existsSync(file)) throw new Error(`MIX file not found: ${file}`)
      const buf = readFileSync(file)
      const mix = parseMix(buf)

      const wanted = [] // { entry, index, name? }
      const seen = new Set()
      const missing = []
      const pick = (entry, index, name) => {
        if (seen.has(index)) return
        seen.add(index)
        wanted.push({ entry, index, name })
      }

      for (const name of args.names ?? []) {
        const id = ra2Crc(String(name))
        const matches = mix.entries.map((e, i) => ({ e, i })).filter(({ e }) => e.id === id && !e.stub)
        if (matches.length === 0) missing.push(`name:${String(name)}`)
        else for (const { e, i } of matches) pick(e, i, String(name))
      }
      for (const idx of args.indexes ?? []) {
        const i = Math.trunc(idx)
        const e = mix.entries[i]
        if (!e || e.stub) missing.push(`index:${i}`)
        else pick(e, i, null)
      }
      for (const raw of args.ids ?? []) {
        const id = parseId(raw)
        const matches = mix.entries.map((e, i) => ({ e, i })).filter(({ e }) => e.id === id && !e.stub)
        if (matches.length === 0) missing.push(`id:${raw}`)
        else for (const { e, i } of matches) pick(e, i, null)
      }

      if (wanted.length === 0) throw new Error('nothing to extract: give names, indexes, or ids (and check the not-found list)')
      if (wanted.length > MAX_EXTRACT_FILES) throw new Error(`too many files selected (${wanted.length}, max ${MAX_EXTRACT_FILES})`)
      let totalBytes = 0
      for (const { entry } of wanted) totalBytes += Math.max(0, entry.size)
      if (totalBytes > MAX_EXTRACT_BYTES) throw new Error(`selection too large (${totalBytes} bytes, max ${MAX_EXTRACT_BYTES})`)

      await mkdir(outDir, { recursive: true })
      const extracted = []
      const usedNames = new Map()
      for (const { entry, index, name } of wanted) {
        let fileName
        if (name !== null) {
          fileName = sanitizeName(name)
          const count = usedNames.get(fileName) ?? 0
          usedNames.set(fileName, count + 1)
          if (count > 0) fileName = fileName.replace(/(\.[A-Za-z0-9]+)?$/, `_${index}$1`)
        } else {
          fileName = `${String(index).padStart(5, '0')}_0x${entry.id.toString(16).padStart(8, '0')}.bin`
        }
        const data = readEntryData(buf, mix, entry)
        const target = path.join(outDir, fileName)
        await writeFile(target, data)
        extracted.push({ index, id: `0x${entry.id.toString(16).padStart(8, '0')}`, name: name ?? undefined, size: data.length, path: target })
      }
      return JSON.stringify({ file, outDir, extracted, missing, totalBytes }, null, 2)
    },
    presentCall: (args) => ({ card: 'generic', title: 'Extract from MIX archive', kind: 'execute', rawInput: args }),
  }))

  ctx.effect(() => ctx.tools.register({
    name: 'mix_launch',
    description: 'Launch XCC Mixer.exe, the GUI browser for C&C MIX archives, passing the MIX file path on its command line. The mixer is a standalone Windows GUI app: this tool only starts it and reports the process id; it cannot read back what the user does in the GUI.',
    parameters: {
      file: { type: 'string', description: 'MIX file path to open; defaults to the configured defaultMix' },
      mixer: { type: 'string', description: 'Mixer executable path; defaults to the configured XCC Mixer.exe' },
    },
    output: { schema: { type: 'string' }, render: textRender },
    async execute(args) {
      const mixer = typeof args.mixer === 'string' && args.mixer !== '' ? args.mixer : defaults.mixerPath
      if (!mixer) throw new Error('no mixer configured and no mixer given')
      if (!existsSync(mixer)) throw new Error(`mixer not found: ${mixer}`)
      const file = resolveFile(args)
      if (!existsSync(file)) throw new Error(`MIX file not found: ${file}`)
      const child = spawn(mixer, [file], { detached: true, stdio: 'ignore', windowsHide: false })
      child.unref()
      return JSON.stringify({
        launched: true,
        pid: child.pid,
        mixer,
        file,
        note: 'The mixer is a GUI app. If it does not open the file automatically, use its file dialog to open it manually.',
      }, null, 2)
    },
    presentCall: (args) => ({ card: 'generic', title: 'Open MIX in XCC Mixer', kind: 'execute', rawInput: args }),
  }))
}
