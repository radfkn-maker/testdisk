/*

    File: file_dat.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dat)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dat(file_stat_t *file_stat);

const file_hint_t file_hint_dat = {
  .extension = "dat",
  .description = "Bitcoin Core Berkeley DB wallet",
  .max_filesize = 100 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_dat
};

/*
 * Berkeley DB meta page header structure.
 * BDB files begin with an 8-byte LSN, then page number, magic, version, pagesize.
 */
struct bdb_meta_header {
  uint8_t  lsn[8];       /* 00-07: Log sequence number */
  uint32_t pgno;          /* 08-11: Page number */
  uint32_t magic;         /* 12-15: Magic number */
  uint32_t version;       /* 16-19: Version */
  uint32_t pagesize;      /* 20-23: Page size */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bdb_magic(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* If we have enough data, try to parse BDB page size from meta header at offset 20 */
  if(buffer_size >= sizeof(struct bdb_meta_header))
  {
    const struct bdb_meta_header *hdr = (const struct bdb_meta_header *)buffer;
    const uint32_t pagesize = le32(hdr->pagesize);
    if(pagesize >= 512 && pagesize <= 65536 && (pagesize & (pagesize - 1)) == 0)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension = file_hint_dat.extension;
      file_recovery_new->min_filesize = pagesize;
      /* Estimate: typical Bitcoin Core wallet is a few hundred pages */
      file_recovery_new->calculated_file_size = (uint64_t)pagesize * 256;
      if(file_recovery_new->blocksize >= 0x18)
      {
        file_recovery_new->file_check = &file_check_size;
      }
      return 1;
    }
  }
  /* Fallback: BDB magic matched but couldn't parse page size */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = 512;
  return 1;
}

/*@
  @ requires buffer_size >= 24;
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bdb_meta(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * Extended BDB signature matched at offset 8.
   * buffer points to file offset 0, so pagesize is at buffer[20].
   */
  uint32_t pagesize;
  if(buffer_size < 24)
    return 0;

  pagesize = le32(*((const uint32_t *)&buffer[20]));

  /* Validate page size: must be power of 2 between 512 and 65536 */
  if(pagesize < 512 || pagesize > 65536 || (pagesize & (pagesize - 1)) != 0)
    return 0;

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = pagesize;
  file_recovery_new->calculated_file_size = (uint64_t)pagesize * 256;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_btc_mkey(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Bitcoin Core encrypted wallet mkey fingerprint (23 bytes).
   * This signature appears in ALL encrypted wallets from v0.8.0 onwards.
   * The wallet is a full BDB file, typically 1-100 MB. */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = 512;
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_btc_record(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Bitcoin Core BDB record markers (key, ckey, mkey, bestblock, etc.).
   * These appear within BDB pages. A recovered fragment is at most one page (4096-8192 bytes). */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = 32;
  file_recovery_new->calculated_file_size = 4096;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_b64_salted(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Base64-encoded OpenSSL "Salted__" prefix: U2FsdGVkX1
   * Encrypted wallet backups are typically small (< 4 KB). */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = 48;
  file_recovery_new->calculated_file_size = 4096;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_dat, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_google_btc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* "com.google.bitcoin.core" at offset 8 in the file.
   * This is the bitcoinj library identifier used by MultiBit and Android wallets.
   * Protobuf-serialized wallets are typically small (< 1 MB). */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_dat.extension;
  file_recovery_new->min_filesize = 64;
  file_recovery_new->calculated_file_size = 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

static void register_header_check_dat(file_stat_t *file_stat)
{
  /* ===== Berkeley DB 4-byte magic numbers (all endian variants) ===== */

  /* Hash DB: 0x00061561 */
  static const unsigned char bdb_hash_le[4] = { 0x61, 0x15, 0x06, 0x00 };
  static const unsigned char bdb_hash_be[4] = { 0x00, 0x06, 0x15, 0x61 };
  /* B-tree DB: 0x00053162 (Bitcoin Core uses this) */
  static const unsigned char bdb_btree_le[4] = { 0x62, 0x31, 0x05, 0x00 };
  static const unsigned char bdb_btree_be[4] = { 0x00, 0x05, 0x31, 0x62 };
  /* Queue DB: 0x00042253 */
  static const unsigned char bdb_queue_le[4] = { 0x53, 0x22, 0x04, 0x00 };
  static const unsigned char bdb_queue_be[4] = { 0x00, 0x04, 0x22, 0x53 };
  /* Log file: 0x00040988 */
  static const unsigned char bdb_log_le[4] = { 0x88, 0x09, 0x04, 0x00 };
  static const unsigned char bdb_log_be[4] = { 0x00, 0x04, 0x09, 0x88 };

  /* Additional Berkeley DB variants */
  static const unsigned char bdb_var1[4] = { 0x00, 0x04, 0x05, 0x71 };
  static const unsigned char bdb_var2[4] = { 0x00, 0x06, 0x31, 0x62 };
  static const unsigned char bdb_var3[4] = { 0x62, 0x31, 0x06, 0x00 };
  static const unsigned char bdb_var4[4] = { 0x71, 0x05, 0x04, 0x00 };

  /* Berkeley DB extended signature at offset 8: pgno(0) + btree magic + version 9 + pagesize 8192 */
  static const unsigned char bdb_extended[24] = {
    0x00, 0x00, 0x00, 0x00, 0x62, 0x31, 0x05, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  /* ===== Bitcoin Core wallet.dat signatures ===== */

  /* Encrypted wallet mkey fingerprint - 23 bytes */
  static const unsigned char btc_mkey_sig[23] = {
    0x04, 0x20, 0xC2, 0x5F, 0x3B, 0xB2, 0xD3, 0x75,
    0x24, 0x47, 0x96, 0xF8, 0x22, 0xAC, 0xDD, 0xB7,
    0x3F, 0x53, 0xD0, 0x24, 0x09, 0x8E, 0xED
  };

  /* Address book name"1 entry - 6 bytes */
  static const unsigned char btc_name1[6] = { 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x31 };

  /* BDB record markers */
  static const unsigned char btc_prefix_key[4] = { 0x04, 'k', 'e', 'y' };
  static const unsigned char btc_key_null[4]   = { 'k', 'e', 'y', 0x00 };
  static const unsigned char btc_ckey[4]       = { 'c', 'k', 'e', 'y' };
  static const unsigned char btc_mkey[4]       = { 'm', 'k', 'e', 'y' };
  static const unsigned char btc_bestblock[9]  = { 'b', 'e', 's', 't', 'b', 'l', 'o', 'c', 'k' };

  /* bestpkey with BDB length prefix - 10 bytes */
  static const unsigned char btc_bestpkey[10] = {
    0x04, 0x06, 0x62, 0x65, 0x73, 0x74, 0x70, 0x6B, 0x65, 0x79
  };

  /* defaultkey with BDB length prefix - 11 bytes */
  static const unsigned char btc_defaultkey[11] = {
    0x04, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x6B, 0x65, 0x79
  };

  /* acentry with BDB length prefix - 8 bytes */
  static const unsigned char btc_acentry[8] = {
    0x07, 0x61, 0x63, 0x65, 0x6E, 0x74, 0x72, 0x79
  };

  /* version with BDB length prefix - 8 bytes */
  static const unsigned char btc_version[8] = {
    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E
  };

  /* minversion with BDB length prefix - 11 bytes */
  static const unsigned char btc_minversion[11] = {
    0x0A, 0x6D, 0x69, 0x6E, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E
  };

  /* bestblock with double BDB length prefix - 11 bytes */
  static const unsigned char btc_bestblock_pfx[11] = {
    0x0A, 0x07, 0x62, 0x65, 0x73, 0x74, 0x62, 0x6C, 0x6F, 0x63, 0x6B
  };

  /* ===== PhotoRec-specific Bitcoin markers ===== */

  /* Base64-encoded OpenSSL "Salted__" : U2FsdGVkX1 - 10 bytes */
  static const unsigned char b64_salted[10] = {
    0x55, 0x32, 0x46, 0x73, 0x64, 0x47, 0x56, 0x6B, 0x58, 0x31
  };

  /* com.google.bitcoin.core at offset 8 - 23 bytes */
  static const unsigned char google_btc_core[23] = {
    0x63, 0x6F, 0x6D, 0x2E, 0x67, 0x6F, 0x6F, 0x67,
    0x6C, 0x65, 0x2E, 0x62, 0x69, 0x74, 0x63, 0x6F,
    0x69, 0x6E, 0x2E, 0x63, 0x6F, 0x72, 0x65
  };

  /* "# KEEP YOUR PRIVATE KEYS SAFE !" - 31 bytes */
  static const unsigned char keep_safe[31] = {
    0x23, 0x20, 0x4B, 0x45, 0x45, 0x50, 0x20, 0x59,
    0x4F, 0x55, 0x52, 0x20, 0x50, 0x52, 0x49, 0x56,
    0x41, 0x54, 0x45, 0x20, 0x4B, 0x45, 0x59, 0x53,
    0x20, 0x53, 0x41, 0x46, 0x45, 0x20, 0x21
  };

  /* Register Berkeley DB magic numbers at offset 0 */
  register_header_check(0, bdb_hash_le, sizeof(bdb_hash_le), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_hash_be, sizeof(bdb_hash_be), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_btree_le, sizeof(bdb_btree_le), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_btree_be, sizeof(bdb_btree_be), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_queue_le, sizeof(bdb_queue_le), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_queue_be, sizeof(bdb_queue_be), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_log_le, sizeof(bdb_log_le), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_log_be, sizeof(bdb_log_be), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_var1, sizeof(bdb_var1), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_var2, sizeof(bdb_var2), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_var3, sizeof(bdb_var3), &header_check_bdb_magic, file_stat);
  register_header_check(0, bdb_var4, sizeof(bdb_var4), &header_check_bdb_magic, file_stat);

  /* Berkeley DB extended signature at offset 8 */
  register_header_check(8, bdb_extended, sizeof(bdb_extended), &header_check_bdb_meta, file_stat);

  /* Bitcoin Core encrypted wallet mkey signature */
  register_header_check(0, btc_mkey_sig, sizeof(btc_mkey_sig), &header_check_btc_mkey, file_stat);

  /* Bitcoin Core record markers */
  register_header_check(0, btc_name1, sizeof(btc_name1), &header_check_btc_record, file_stat);
  register_header_check(0, btc_prefix_key, sizeof(btc_prefix_key), &header_check_btc_record, file_stat);
  register_header_check(0, btc_key_null, sizeof(btc_key_null), &header_check_btc_record, file_stat);
  register_header_check(0, btc_ckey, sizeof(btc_ckey), &header_check_btc_record, file_stat);
  register_header_check(0, btc_mkey, sizeof(btc_mkey), &header_check_btc_record, file_stat);
  register_header_check(0, btc_bestblock, sizeof(btc_bestblock), &header_check_btc_record, file_stat);
  register_header_check(0, btc_bestpkey, sizeof(btc_bestpkey), &header_check_btc_record, file_stat);
  register_header_check(0, btc_defaultkey, sizeof(btc_defaultkey), &header_check_btc_record, file_stat);
  register_header_check(0, btc_acentry, sizeof(btc_acentry), &header_check_btc_record, file_stat);
  register_header_check(0, btc_version, sizeof(btc_version), &header_check_btc_record, file_stat);
  register_header_check(0, btc_minversion, sizeof(btc_minversion), &header_check_btc_record, file_stat);
  register_header_check(0, btc_bestblock_pfx, sizeof(btc_bestblock_pfx), &header_check_btc_record, file_stat);

  /* PhotoRec-specific markers */
  register_header_check(0, b64_salted, sizeof(b64_salted), &header_check_b64_salted, file_stat);
  register_header_check(8, google_btc_core, sizeof(google_btc_core), &header_check_google_btc, file_stat);
  register_header_check(0, keep_safe, sizeof(keep_safe), &header_check_btc_record, file_stat);
}
#endif
