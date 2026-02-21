/*

    File: file_prvkey.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prvkey)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_prvkey(file_stat_t *file_stat);

const file_hint_t file_hint_prvkey = {
  .extension = "key",
  .description = "Cryptocurrency private key",
  .max_filesize = 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_prvkey
};

/*@
  @ requires separation: \separated(&file_hint_prvkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_generic_key(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * Generic private key markers: privkey, priv_key, private_key, priv, addr,
   * wallet, master, reserve.
   * These keywords appear at the start of key backup files, wallet exports,
   * and configuration fragments. Size is indeterminate; use conservative max.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_prvkey.extension;
  file_recovery_new->min_filesize = 32;
  /* Key files and fragments are typically small */
  file_recovery_new->calculated_file_size = 65536;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_prvkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_openssl_salted(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * OpenSSL "Salted__" header (8 bytes): 0x53616C7465645F5F
   * Followed by 8 bytes of salt, then the encrypted data.
   * OpenSSL encrypted files have known structure:
   *   8 (header) + 8 (salt) + N (ciphertext, multiple of block size)
   * Typical encrypted key backups are small (< 64 KB).
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_prvkey.extension;
  file_recovery_new->min_filesize = 48;  /* header + salt + at least 2 AES blocks */
  file_recovery_new->calculated_file_size = 65536;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_prvkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_pem_key(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * PEM-encoded private keys:
   *   "BEGIN EC PRIVATE KEY"   - ECDSA key (~220-350 bytes total)
   *   "BEGIN PRIVATE KEY"      - PKCS#8 key (variable, ~200-3300 bytes)
   *
   * PEM files have a well-defined structure:
   *   -----BEGIN <type>-----\n
   *   <base64 data>\n
   *   -----END <type>-----\n
   *
   * EC private keys (secp256k1, used by Bitcoin) are ~280 bytes.
   * RSA 2048-bit keys are ~1700 bytes. RSA 4096 are ~3300 bytes.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_prvkey.extension;
  file_recovery_new->min_filesize = 100;
  /* PEM keys are at most a few KB */
  file_recovery_new->calculated_file_size = 8192;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_prvkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_pgp_armored(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * PGP ASCII-armored data: "-----BEGIN PGP"
   * Can be a PGP private key, public key, signed message, or encrypted data.
   * PGP key files are typically 1-10 KB.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = "pgp";
  file_recovery_new->min_filesize = 100;
  file_recovery_new->calculated_file_size = 65536;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_prvkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_sqlite(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * SQLite database header: "SQLite format 3\0" (16 bytes)
   * Many cryptocurrency wallets use SQLite (Electrum v2+, various altcoin wallets).
   * The page size is stored at offset 16 (2 bytes, big-endian).
   * File size = page_size * page_count (page_count at offset 28, 4 bytes BE).
   */
  uint16_t page_size;
  uint32_t page_count;

  if(buffer_size < 100)  /* SQLite header is at least 100 bytes */
    return 0;

  page_size = (buffer[16] << 8) | buffer[17];
  /* SQLite page size: 512 to 65536 (0 means 65536) */
  if(page_size == 0)
    page_size = 1;  /* Will be multiplied as 65536 below */
  else if(page_size < 512 || (page_size & (page_size - 1)) != 0)
    return 0;

  page_count = ((uint32_t)buffer[28] << 24) | ((uint32_t)buffer[29] << 16) |
               ((uint32_t)buffer[30] << 8) | buffer[31];

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = "db";
  file_recovery_new->min_filesize = 512;

  if(page_count > 0 && page_count < 1000000)
  {
    uint64_t real_page_size = (page_size == 1) ? 65536 : page_size;
    file_recovery_new->calculated_file_size = real_page_size * page_count;
  }
  else
  {
    /* Unknown page count, use reasonable max for wallet DBs */
    file_recovery_new->calculated_file_size = 50 * 1024 * 1024;
  }

  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

static void register_header_check_prvkey(file_stat_t *file_stat)
{
  /* ===== Generic private key markers ===== */
  static const unsigned char kw_privkey[7]     = { 'p','r','i','v','k','e','y' };
  static const unsigned char kw_priv_key[8]    = { 'p','r','i','v','_','k','e','y' };
  static const unsigned char kw_private_key[11] = { 'p','r','i','v','a','t','e','_','k','e','y' };
  static const unsigned char kw_priv[4]        = { 'p','r','i','v' };
  static const unsigned char kw_addr[4]        = { 'a','d','d','r' };
  static const unsigned char kw_wallet[6]      = { 'w','a','l','l','e','t' };
  static const unsigned char kw_master[6]      = { 'm','a','s','t','e','r' };
  static const unsigned char kw_reserve[7]     = { 'r','e','s','e','r','v','e' };

  /* ===== OpenSSL encrypted file header ===== */
  /* "Salted__" - 8 bytes */
  static const unsigned char openssl_salted[8] = {
    0x53, 0x61, 0x6C, 0x74, 0x65, 0x64, 0x5F, 0x5F
  };

  /* ===== PEM private key headers ===== */
  /* "BEGIN EC PRIVATE KEY" - 20 bytes */
  static const unsigned char pem_ec[20] = {
    'B','E','G','I','N',' ','E','C',' ','P','R','I','V','A','T','E',' ','K','E','Y'
  };
  /* "BEGIN PRIVATE KEY" - 17 bytes */
  static const unsigned char pem_pkcs8[17] = {
    0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x52,
    0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4B, 0x45, 0x59
  };

  /* ===== PGP armored ===== */
  /* "-----BEGIN PGP" - 14 bytes */
  static const unsigned char pgp_header[14] = {
    '-','-','-','-','-','B','E','G','I','N',' ','P','G','P'
  };

  /* ===== SQLite database ===== */
  /* "SQLite format 3\0" - 16 bytes */
  static const unsigned char sqlite_header[16] = {
    'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3', 0x00
  };

  /* Register generic key markers */
  register_header_check(0, kw_privkey, sizeof(kw_privkey), &header_check_generic_key, file_stat);
  register_header_check(0, kw_priv_key, sizeof(kw_priv_key), &header_check_generic_key, file_stat);
  register_header_check(0, kw_private_key, sizeof(kw_private_key), &header_check_generic_key, file_stat);
  register_header_check(0, kw_priv, sizeof(kw_priv), &header_check_generic_key, file_stat);
  register_header_check(0, kw_addr, sizeof(kw_addr), &header_check_generic_key, file_stat);
  register_header_check(0, kw_wallet, sizeof(kw_wallet), &header_check_generic_key, file_stat);
  register_header_check(0, kw_master, sizeof(kw_master), &header_check_generic_key, file_stat);
  register_header_check(0, kw_reserve, sizeof(kw_reserve), &header_check_generic_key, file_stat);

  /* Register OpenSSL Salted__ */
  register_header_check(0, openssl_salted, sizeof(openssl_salted), &header_check_openssl_salted, file_stat);

  /* Register PEM private key headers */
  register_header_check(0, pem_ec, sizeof(pem_ec), &header_check_pem_key, file_stat);
  register_header_check(0, pem_pkcs8, sizeof(pem_pkcs8), &header_check_pem_key, file_stat);

  /* Register PGP armored header */
  register_header_check(0, pgp_header, sizeof(pgp_header), &header_check_pgp_armored, file_stat);

  /* Register SQLite header */
  register_header_check(0, sqlite_header, sizeof(sqlite_header), &header_check_sqlite, file_stat);
}
#endif
