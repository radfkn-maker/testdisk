# CLAUDE.md — AI Assistant Guide for testdisk/PhotoRec Crypto Wallet Extension

## Project Overview

This repository is a focused extension of the [TestDisk/PhotoRec](https://www.cgsecurity.org/wiki/TestDisk) project. The goal is to add **cryptocurrency wallet and private key recovery** to PhotoRec's data carving engine by implementing dedicated C file-format handlers.

The repository contains:
- **Template source files** demonstrating the PhotoRec file-handler pattern
- **Cryptocurrency wallet signatures** for detection
- **Build system** integration (GNU Autotools)

---

## Repository Structure

```
testdisk/
├── CLAUDE.md                  # This file
├── README.md                  # Task specification
├── photorec.sig               # Cryptocurrency wallet binary signatures (reference)
├── photorecsig_updated        # Optimized signature set (high-specificity, ≥12 bytes)
└── src/
    ├── Makefile.am            # GNU Autotools build configuration (~530 lines)
    ├── file_bac.c             # Template: Bacula backup handler (block-chain parsing)
    ├── file_mp3.c             # Template: MP3 handler (complex state machine, ID3 tags)
    └── file_wallet.c          # Template: Minimal crypto wallet handler (signature matching)
```

### Files to Implement (per README.md task spec)

| File | Format | Recovery Strategy |
|------|--------|-------------------|
| `src/file_dat.c` | Bitcoin Core / Berkeley DB wallet | Header-defined size |
| `src/file_multibit.c` | MultiBit Classic/HD wallet | Fixed/max size fallback |
| `src/file_electrum.c` | Electrum JSON / AES-encrypted | Max size fallback |
| `src/file_prvkey.c` | Raw private keys, PEM, encrypted backups | Known fixed sizes |

---

## Core Concepts: PhotoRec File Handler Pattern

Every PhotoRec format handler must implement these three components. Study `src/file_bac.c` and `src/file_wallet.c` as canonical examples.

### 1. `file_hint_t` — Format Registration Descriptor

```c
const file_hint_t file_hint_XXX = {
  .extension        = "ext",                  // output file extension
  .description      = "Human readable name",
  .max_filesize     = 10 * 1024 * 1024,       // hard upper limit in bytes
  .recover          = 1,                       // 1 = enable recovery
  .enable_by_default = 1,
  .register_header_check = &register_header_check_XXX
};
```

### 2. `header_check_XXX()` — Signature Validation & State Initialization

Called when PhotoRec finds a matching byte sequence at offset 0 (or registered offset).

```c
static int header_check_XXX(
    const unsigned char *buffer,
    const unsigned int buffer_size,
    const unsigned int safe_header_only,
    const file_recovery_t *file_recovery,
    file_recovery_t *file_recovery_new)
{
  // Validate additional header bytes beyond the registered signature
  if (buffer_size < sizeof(struct xxx_header))
    return 0;

  reset_file_recovery(file_recovery_new);           // ALWAYS call first
  file_recovery_new->extension = file_hint_XXX.extension;

  // Set size constraints (CRUCIAL — see File Size Strategy below)
  file_recovery_new->min_filesize = MINIMUM_BYTES;
  file_recovery_new->calculated_file_size = EXACT_SIZE_IF_KNOWN;

  // Attach callbacks if iterative parsing is needed
  file_recovery_new->data_check = &data_check_XXX;
  file_recovery_new->file_check = &file_check_size;

  return 1;  // 0 = reject this candidate
}
```

### 3. `register_header_check_XXX()` — Signature Table Registration

```c
static void register_header_check_XXX(file_stat_t *file_stat)
{
  static const unsigned char magic[N] = { 0xXX, 0xXX, ... };
  // Second arg = byte offset from file start where signature occurs
  register_header_check(0, magic, sizeof(magic), &header_check_XXX, file_stat);
  // Register multiple signatures by calling register_header_check() multiple times
}
```

### 4. `data_check_XXX()` — Iterative Payload Parsing (optional)

Used when file boundaries must be determined by parsing internal structure (e.g., block chains).

```c
static data_check_t data_check_XXX(
    const unsigned char *buffer,
    const unsigned int buffer_size,
    file_recovery_t *file_recovery)
{
  // Walk forward through buffer using calculated_file_size as cursor
  while (file_recovery->calculated_file_size + buffer_size/2 >= file_recovery->file_size &&
         file_recovery->calculated_file_size + HEADER_SIZE < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i = file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    const struct xxx_block *blk = (const struct xxx_block *)&buffer[i];

    if (/* invalid block */)
      return DC_STOP;   // File boundary reached

    file_recovery->calculated_file_size += block_size;
  }
  return DC_CONTINUE;   // Keep reading
}
```

---

## File Size Strategy (Critical)

PhotoRec uses `calculated_file_size` to determine where to stop carving. Incorrect sizing leads to:
- **Too small**: truncated/corrupt recovered files
- **Too large**: enormous garbage files consuming disk space

| Scenario | Approach | Example |
|----------|----------|---------|
| **Fixed-size format** | Set `calculated_file_size` to exact byte count | Raw EC private key = 32 bytes |
| **Header-encoded size** | Parse size field from header, assign to `calculated_file_size` | BerkeleyDB page-size field |
| **Unknown/variable size** | Set `max_filesize` as a cap; use `data_check` for boundary detection | Electrum JSON wallets |
| **Block-chained format** | Use `data_check` to walk blocks, accumulate sizes | Bacula (see file_bac.c) |

Always call `file_check_size` as `file_recovery_new->file_check` when setting `calculated_file_size`.

---

## Coding Conventions

### Required Conditional Compilation Guard

Every handler file must be wrapped with:

```c
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xxx)
// ... entire file content ...
#endif
```

This allows single-format compilation for Frama-C verification.

### Standard Include Block

```c
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"   // add if using be32()/le32() or other utilities
#include "log.h"      // add if using log_trace/log_error
```

### Packed Struct Definition

```c
struct xxx_header {
  uint32_t field1;
  uint16_t field2;
  char     magic[4];
} __attribute__ ((gcc_struct, __packed__));
```

### Endianness Helpers

- `be32(x)` — read big-endian uint32 from pointer
- `le32(x)` — read little-endian uint32 from pointer
- `be16(x)`, `le16(x)` — 16-bit variants

### Logging

```c
log_trace("file_xxx.c: message %llu\n", (long long unsigned)value);
log_error("file_xxx.c: invalid block at %llu\n", (long long unsigned)offset);
```

Wrap debug logging in `#ifdef DEBUG_XXX` / `#endif`.

### Frama-C ACSL Annotations

Prepend formal specifications to all non-trivial functions:

```c
/*@
  @ requires buffer_size >= sizeof(struct xxx_header);
  @ requires separation: \separated(&file_hint_xxx, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
```

For `data_check` functions include loop variants:

```c
/*@
  @ loop assigns file_recovery->calculated_file_size;
  @ loop variant EXPR;
  @*/
```

---

## Signature Reference (`photorec.sig`)

Key binary signatures available for the new modules:

### Bitcoin Core / Berkeley DB (`file_dat.c`)
```
# Berkeley DB magic + page size variants
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x62\x63\x64 (at offset 12: 0x00053162, 0x00042162, etc.)
# wallet.dat encrypted key marker (23 bytes, high specificity)
\x04\x6d\x6b\x65\x79\x43\x72\x79\x70\x74\x65\x64\x53\x65\x63\x72\x65\x74\x31\x2e\x30\x00\x00
```

### MultiBit (`file_multibit.c`)
```
# MultiBit Bitcoin production header
\x0a\x16 org.bitcoin.production
# MultiBit Dogecoin production header
\x0a\x17 org.dogecoin.production
```

### Electrum (`file_electrum.c`)
```
# JSON key markers (with single/double quote variants)
'addr_history'  /  "addr_history"
'seed'          /  "seed"
'keystore'      /  "keystore"
```

### Private Keys (`file_prvkey.c`)
```
# PEM private key
-----BEGIN EC PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
# OpenSSL encrypted
Salted__
# PGP armor
-----BEGIN PGP MESSAGE-----
```

Full details are in `photorec.sig` and `photorecsig_updated`.

---

## Build System Integration (`src/Makefile.am`)

### Adding a New Module

1. Find the `file_C` variable definition in `Makefile.am` (alphabetically ordered list)
2. Add new files in alphabetical order:

```makefile
# Example: adding file_dat.c, file_electrum.c, file_multibit.c, file_prvkey.c
file_dat.c \
...
file_electrum.c \
...
file_multibit.c \
...
file_prvkey.c \
```

3. Add corresponding Frama-C verification targets following the existing pattern:

```makefile
session_dat.framac: file_dat.c ...
session_electrum.framac: file_electrum.c ...
```

### Build Commands

```bash
./configure          # Generate Makefiles from configure.ac
make                 # Build all targets (testdisk, photorec, fidentify)
make photorec        # Build PhotoRec only
```

### Single-Format Test Build

```bash
make CFLAGS="-DSINGLE_FORMAT -DSINGLE_FORMAT_dat" photorec
```

### Frama-C Formal Verification (optional)

```bash
make session_dat.framac
frama-c-gui session_dat.framac   # Interactive proof browser
```

---

## Development Workflow

1. **Read the templates** — understand `file_bac.c` (block parsing), `file_mp3.c` (state machine), `file_wallet.c` (signature-only)
2. **Check `photorec.sig`** — identify all relevant signatures for the target format
3. **Implement** in `src/file_XXX.c` following the three-component pattern above
4. **Update `src/Makefile.am`** — add the new `.c` file to the `file_C` list
5. **Build** with `make photorec` to verify compilation
6. **Test** manually with a disk image containing known wallet files
7. **Commit** with a descriptive message referencing the format name

### Commit Message Convention

```
Add file_dat.c: Bitcoin Core/Berkeley DB wallet recovery

- Registers BDB magic signatures at byte offset 12
- Parses page size from BDB header for accurate file sizing
- Handles encrypted wallet mkey marker as secondary signature
```

---

## Key Internal API Reference

| Function/Type | Purpose |
|--------------|---------|
| `reset_file_recovery(file_recovery_new)` | Initialize new recovery context — always call first in `header_check` |
| `register_header_check(offset, sig, len, fn, stat)` | Register a binary signature at given file offset |
| `file_check_size` | Standard file-check callback for size-bounded recovery |
| `DC_CONTINUE` | Return from `data_check` to continue carving |
| `DC_STOP` | Return from `data_check` to stop carving (file boundary found) |
| `be32(ptr)` / `le32(ptr)` | Read big/little-endian uint32 from pointer |
| `PHOTOREC_MAX_FILE_SIZE` | Global maximum carve size constant |
| `log_trace()`, `log_error()` | Logging at trace and error levels |

### `file_recovery_t` Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `extension` | `const char *` | Output file extension |
| `calculated_file_size` | `uint64_t` | Expected size (drives carving stop point) |
| `file_size` | `uint64_t` | Current size carved so far |
| `min_filesize` | `uint64_t` | Minimum valid file size |
| `blocksize` | `uint32_t` | Processing block size (used in `data_check` guard) |
| `data_check` | function ptr | Called continuously during carving |
| `file_check` | function ptr | Called at end to validate the recovered file |
| `file_rename` | function ptr | Optional: rename based on content inspection |

---

## Important Constraints

- **No C++ or external libraries** — pure C, standard library only (`string.h`, `stdio.h`, `stdint.h`)
- **Packed structs required** for all binary format structures: `__attribute__ ((gcc_struct, __packed__))`
- **Always bounds-check** before casting buffer to struct: `if (buffer_size < sizeof(struct xxx)) return 0;`
- **Never dereference unvalidated pointers** — all buffer reads must be within `buffer_size`
- **Endianness matters** — use `be32()`/`le32()` helpers, never raw pointer casts for multi-byte fields
- **`calculated_file_size` must be set** or files will be carved up to `max_filesize` (potentially huge)
- **All Frama-C annotations are optional** but help verify correctness; include `/*@ ... @*/` blocks for all public functions

---

## Git Branch

Development branch: `claude/claude-md-mm5jqcslqax1d1y3-Of0Fq`

Push with:
```bash
git push -u origin claude/claude-md-mm5jqcslqax1d1y3-Of0Fq
```
