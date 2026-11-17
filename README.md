# dsh-ra2-mix

A [DeepSeek Harness](https://github.com/deepseek-ai) Host plugin for Red Alert 2 /
Yuri's Revenge **MIX archives** (the format read by XCC Mixer).

## Tools

Agent tools, prefixed `mix_`:

| Tool | Purpose |
| --- | --- |
| `mix_info` | Header (flags, encryption state) plus a paged entry list (id / offset / size) |
| `mix_hash` | RA2 MIX file ID (CRC32 hash) for a file name |
| `mix_extract` | Extract entries by name, index, or ID into a directory |
| `mix_launch` | Launch `XCC Mixer.exe` with the MIX file |

## Install

Requires DeepSeek Harness 0.2 or newer.

```bash
plugin_manager install_bundle target=github:AmahaHanasaki/dsh-ra2-mix
# or: plugin_manager install_bundle target=<path-to-this-repo>
```

## Format notes

- Header: flags (u32) + count (u16) + body size (u32), then 12-byte entries
  (id, offset, size).
- Encrypted archives (flags & 0x20000): an 80-byte RSA-wrapped Blowfish key follows the
  flags; the count/size/index block is Blowfish-ECB encrypted. File data itself stays in
  plaintext (verified against real Mental Omega archives).
- Entry IDs are the CRC32 (zlib) of the upper-cased file name, padded to a 4-byte
  boundary with a small fill rule; `mix_hash` implements the same hash.

## Configuration

Edit the plugin row config in the profile:

| Key | Meaning |
| --- | --- |
| `mixerPath` | Default `XCC Mixer.exe` path used by `mix_launch` |
| `defaultMix` | MIX file used when a tool call omits `file` |

Both are empty by default. The external mixer is optional; reading and extracting work
without it.

## Credits

MIX format details cross-checked against the `ra2-mix` (MPL-2.0) and `cnc-formats`
(MIT/Apache-2.0) Rust crates.

## License

MIT
