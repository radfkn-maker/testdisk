/*

    File: file_multibit.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_multibit)
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
static void register_header_check_multibit(file_stat_t *file_stat);

const file_hint_t file_hint_multibit = {
  .extension = "wallet",
  .description = "MultiBit Classic and HD wallet",
  .max_filesize = 10 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_multibit
};

/*@
  @ requires separation: \separated(&file_hint_multibit, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_multibit_protobuf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * MultiBit Classic wallets use bitcoinj protobuf serialization.
   * The file starts with a protobuf field for network_identifier:
   *   field 1, wire type 2 (length-delimited) = 0x0A
   *   length = 0x16 (22 bytes)
   *   value = "org.bitcoin.production"
   *
   * Protobuf wallets are typically small: 1 KB to a few hundred KB.
   * Set calculated_file_size to a reasonable upper bound.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_multibit.extension;
  file_recovery_new->min_filesize = 24;
  /* Protobuf wallets rarely exceed 1 MB */
  file_recovery_new->calculated_file_size = 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_multibit, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_multibit_header(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
   * MultiBit HD wallet files start with the ASCII header "MULTIBIT " or "MULTABIT".
   * These are AES-encrypted protobuf files used by MultiBit HD.
   * Typical size: 1 KB to 5 MB.
   */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_multibit.extension;
  file_recovery_new->min_filesize = 64;
  /* MultiBit HD encrypted wallets can be up to a few MB */
  file_recovery_new->calculated_file_size = 5 * 1024 * 1024;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->file_check = &file_check_size;
  }
  return 1;
}

static void register_header_check_multibit(file_stat_t *file_stat)
{
  /* MultiBit Classic: bitcoinj protobuf "org.bitcoin.production" - 24 bytes */
  static const unsigned char multibit_protobuf[24] = {
    0x0A, 0x16, 0x6F, 0x72, 0x67, 0x2E, 0x62, 0x69,
    0x74, 0x63, 0x6F, 0x69, 0x6E, 0x2E, 0x70, 0x72,
    0x6F, 0x64, 0x75, 0x63, 0x74, 0x69, 0x6F, 0x6E
  };

  /* MultiBit HD header: "MULTIBIT " - 9 bytes */
  static const unsigned char multibit_hd_header[9] = {
    0x4D, 0x55, 0x4C, 0x54, 0x49, 0x42, 0x49, 0x54, 0x20
  };

  /* MultiBit alternate header: "MULTABIT" - 8 bytes */
  static const unsigned char multabit_header[8] = {
    0x4D, 0x55, 0x4C, 0x54, 0x41, 0x42, 0x49, 0x54
  };

  register_header_check(0, multibit_protobuf, sizeof(multibit_protobuf), &header_check_multibit_protobuf, file_stat);
  register_header_check(0, multibit_hd_header, sizeof(multibit_hd_header), &header_check_multibit_header, file_stat);
  register_header_check(0, multabit_header, sizeof(multabit_header), &header_check_multibit_header, file_stat);
}
#endif
