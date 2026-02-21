/*

    File: file_list.c

    Copyright (C) 2007-2024 Christophe GRENIER <grenier@cgsecurity.org>

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/* Existing file format hints */
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bac)
extern const file_hint_t file_hint_bac;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mp3)
extern const file_hint_t file_hint_mp3;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wallet)
extern const file_hint_t file_hint_wallet;
#endif

/* New cryptocurrency wallet and key recovery hints */
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dat)
extern const file_hint_t file_hint_dat;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_multibit)
extern const file_hint_t file_hint_multibit;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_electrum)
extern const file_hint_t file_hint_electrum;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prvkey)
extern const file_hint_t file_hint_prvkey;
#endif

file_hint_t file_hint_table[] = {
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bac)
  &file_hint_bac,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dat)
  &file_hint_dat,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_electrum)
  &file_hint_electrum,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mp3)
  &file_hint_mp3,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_multibit)
  &file_hint_multibit,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prvkey)
  &file_hint_prvkey,
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wallet)
  &file_hint_wallet,
#endif
  NULL
};
