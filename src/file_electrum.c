/*

    File: file_electrum.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_electrum)
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
static void register_header_check_electrum(file_stat_t *file_stat);

const file_hint_t file_hint_electrum = {
  .extension = "wallet",
  .description = "Electrum and JSON cryptocurrency wallet",
  .max_filesize = 10 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_electrum
};

/*@
  @ requires separation: \separated(&file_hint_electrum, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_electrum_json(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * Electrum wallets are JSON files containing keys like:
   *   {"addr_history": ...}, {"seed": ...}, {"keystore": ...}
   * Also matches generic JSON wallet keywords: keystore, keypairs,
   * seed_version, imported, seed, master_public_key, wallet_type.
   *
   * JSON wallet files have indeterminate size. Set a reasonable
   * maximum to prevent run-away carving.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_electrum.extension;
  file_recovery_new->min_filesize = 50;
  /* JSON wallets rarely exceed 2 MB */
  file_recovery_new->calculated_file_size = 2 * 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_electrum, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bip32_key(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * BIP32 extended keys: xprv (private) and xpub (public).
   * Base58Check-encoded extended keys are exactly 111 characters.
   * These may appear in wallet files or standalone key exports.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_electrum.extension;
  file_recovery_new->min_filesize = 111;
  file_recovery_new->calculated_file_size = 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_electrum, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_armory_ext(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * Armory wallet extended signatures:
   *   ARGY-enc (encrypted root key), ARGY-root (root key identifier),
   *   watchonly (watch-only marker), and BA WALLET magic variants.
   * Armory wallets are typically 100 KB to 10 MB.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_electrum.extension;
  file_recovery_new->min_filesize = 64;
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_electrum, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_blockchain_json(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * Blockchain.info wallet signatures:
   *   "blockchain.info", {"guid":, {"payload":
   * These are JSON files. Use "json" extension to distinguish from
   * Electrum/Armory wallet files.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = "json";
  file_recovery_new->min_filesize = 50;
  file_recovery_new->calculated_file_size = 2 * 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

static void register_header_check_electrum(file_stat_t *file_stat)
{
  /* ===== Electrum & JSON wallet keywords ===== */
  static const unsigned char kw_keystore[8]          = { 'k','e','y','s','t','o','r','e' };
  static const unsigned char kw_keypairs[8]          = { 'k','e','y','p','a','i','r','s' };
  static const unsigned char kw_seed_version[12]     = { 's','e','e','d','_','v','e','r','s','i','o','n' };
  static const unsigned char kw_imported[8]          = { 'i','m','p','o','r','t','e','d' };
  static const unsigned char kw_seed[4]              = { 's','e','e','d' };
  static const unsigned char kw_master_public_key[17] = {
    'm','a','s','t','e','r','_','p','u','b','l','i','c','_','k','e','y'
  };
  static const unsigned char kw_wallet_type[11]      = { 'w','a','l','l','e','t','_','t','y','p','e' };

  /* ===== BIP32 / HD wallet markers ===== */
  static const unsigned char bip32_xprv[4] = { 'x','p','r','v' };
  static const unsigned char bip32_xpub[4] = { 'x','p','u','b' };

  /* ===== Armory wallet extended signatures ===== */
  /* ARGY-enc (encrypted root key) - 8 bytes */
  static const unsigned char armory_enc[8] = {
    0x41, 0x52, 0x47, 0x59, 0x2D, 0x65, 0x6E, 0x63
  };
  /* ARGY-root (root key identifier) - 9 bytes */
  static const unsigned char armory_root[9] = {
    0x41, 0x52, 0x47, 0x59, 0x2D, 0x72, 0x6F, 0x6F, 0x74
  };
  /* watchonly marker - 9 bytes */
  static const unsigned char armory_watchonly[9] = {
    0x77, 0x61, 0x74, 0x63, 0x68, 0x6F, 0x6E, 0x6C, 0x79
  };
  /* Armory BA WALLE\0 magic - 7 bytes */
  static const unsigned char armory_magic1[7] = {
    0xBA, 0x57, 0x41, 0x4C, 0x4C, 0x45, 0x00
  };
  /* Armory BA WALLET magic (full) - 7 bytes */
  static const unsigned char armory_magic2[7] = {
    0xBA, 0x57, 0x41, 0x4C, 0x4C, 0x45, 0x54
  };

  /* ===== Electrum v1 wallet signatures ===== */
  /* {'addr_history': (single quotes) - 16 bytes */
  static const unsigned char electrum_v1_sq[16] = {
    0x7B, 0x27, 0x61, 0x64, 0x64, 0x72, 0x5F, 0x68,
    0x69, 0x73, 0x74, 0x6F, 0x72, 0x79, 0x27, 0x3A
  };
  /* Electrum v1 pretty-printed {'addr_history': - 21 bytes */
  static const unsigned char electrum_v1_pp[21] = {
    0x7B, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x27, 0x61,
    0x64, 0x64, 0x72, 0x5F, 0x68, 0x69, 0x73, 0x74,
    0x6F, 0x72, 0x79, 0x27, 0x3A
  };
  /* {"addr_history": (double quotes) - 16 bytes */
  static const unsigned char electrum_v1_dq[16] = {
    0x7B, 0x22, 0x61, 0x64, 0x64, 0x72, 0x5F, 0x68,
    0x69, 0x73, 0x74, 0x6F, 0x72, 0x79, 0x22, 0x3A
  };
  /* {"seed": - 8 bytes */
  static const unsigned char electrum_seed[8] = {
    0x7B, 0x22, 0x73, 0x65, 0x65, 0x64, 0x22, 0x3A
  };
  /* {"keystore": - 12 bytes */
  static const unsigned char electrum_keystore[12] = {
    0x7B, 0x22, 0x6B, 0x65, 0x79, 0x73, 0x74, 0x6F,
    0x72, 0x65, 0x22, 0x3A
  };

  /* ===== Blockchain.info wallet signatures ===== */
  /* "blockchain.info" - 15 bytes */
  static const unsigned char blockchain_info[15] = {
    0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x63, 0x68, 0x61,
    0x69, 0x6E, 0x2E, 0x69, 0x6E, 0x66, 0x6F
  };
  /* {"guid": - 8 bytes */
  static const unsigned char blockchain_guid[8] = {
    0x7B, 0x22, 0x67, 0x75, 0x69, 0x64, 0x22, 0x3A
  };
  /* {"payload": - 11 bytes */
  static const unsigned char blockchain_payload[11] = {
    0x7B, 0x22, 0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61,
    0x64, 0x22, 0x3A
  };

  /* Register Electrum & JSON wallet keywords */
  register_header_check(0, kw_keystore, sizeof(kw_keystore), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_keypairs, sizeof(kw_keypairs), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_seed_version, sizeof(kw_seed_version), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_imported, sizeof(kw_imported), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_seed, sizeof(kw_seed), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_master_public_key, sizeof(kw_master_public_key), &header_check_electrum_json, file_stat);
  register_header_check(0, kw_wallet_type, sizeof(kw_wallet_type), &header_check_electrum_json, file_stat);

  /* Register BIP32 markers */
  register_header_check(0, bip32_xprv, sizeof(bip32_xprv), &header_check_bip32_key, file_stat);
  register_header_check(0, bip32_xpub, sizeof(bip32_xpub), &header_check_bip32_key, file_stat);

  /* Register Armory extended signatures */
  register_header_check(0, armory_enc, sizeof(armory_enc), &header_check_armory_ext, file_stat);
  register_header_check(0, armory_root, sizeof(armory_root), &header_check_armory_ext, file_stat);
  register_header_check(0, armory_watchonly, sizeof(armory_watchonly), &header_check_armory_ext, file_stat);
  register_header_check(0, armory_magic1, sizeof(armory_magic1), &header_check_armory_ext, file_stat);
  register_header_check(0, armory_magic2, sizeof(armory_magic2), &header_check_armory_ext, file_stat);

  /* Register Electrum v1 signatures */
  register_header_check(0, electrum_v1_sq, sizeof(electrum_v1_sq), &header_check_electrum_json, file_stat);
  register_header_check(0, electrum_v1_pp, sizeof(electrum_v1_pp), &header_check_electrum_json, file_stat);
  register_header_check(0, electrum_v1_dq, sizeof(electrum_v1_dq), &header_check_electrum_json, file_stat);
  register_header_check(0, electrum_seed, sizeof(electrum_seed), &header_check_electrum_json, file_stat);
  register_header_check(0, electrum_keystore, sizeof(electrum_keystore), &header_check_electrum_json, file_stat);

  /* Register Blockchain.info signatures (json extension) */
  register_header_check(0, blockchain_info, sizeof(blockchain_info), &header_check_blockchain_json, file_stat);
  register_header_check(0, blockchain_guid, sizeof(blockchain_guid), &header_check_blockchain_json, file_stat);
  register_header_check(0, blockchain_payload, sizeof(blockchain_payload), &header_check_blockchain_json, file_stat);
}
#endif
