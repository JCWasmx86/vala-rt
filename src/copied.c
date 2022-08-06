/* Retrieves the DWARF descriptor for debugaltlink data.
   Copyright (C) 2014, 2018 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#define _GNU_SOURCE
#include <assert.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUGINFO_PATH "/usr/lib/debug"

static char *
__vala_rt__libdw_filepath (const char *debugdir, const char *dir, const char *file)
{
  if (file == NULL)
    return NULL;

  if (file[0] == '/')
    return strdup (file);

  if (dir != NULL && dir[0] == '/')
    {
      size_t dirlen = strlen (dir);
      size_t filelen = strlen (file);
      size_t len = dirlen + 1 + filelen + 1;
      char  *path = malloc (len);
      if (path != NULL)
        {
          char *c = mempcpy (path, dir, dirlen);
          if (dir[dirlen - 1] != '/')
            *c++ = '/';
          mempcpy (c, file, filelen + 1);
        }
      return path;
    }

  if (debugdir != NULL)
    {
      size_t debugdirlen = strlen (debugdir);
      size_t dirlen = dir != NULL ? strlen (dir) : 0;
      size_t filelen = strlen (file);
      size_t len = debugdirlen + 1 + dirlen + 1 + filelen + 1;
      char  *path = malloc (len);
      if (path != NULL)
        {
          char *c = mempcpy (path, debugdir, debugdirlen);
          if (dirlen > 0)
            {
              c = mempcpy (c, dir, dirlen);
              if (dir[dirlen - 1] != '/')
                *c++ = '/';
            }
          mempcpy (c, file, filelen + 1);
          return path;
        }
    }

  return NULL;
}

// This function was written by me
int
__vala_rt_find_debuglink (Dwfl_Module *module, Elf *elf)
{
  char        data[512] = { 0 };
  GElf_Word   word;
  const char *name = dwelf_elf_gnu_debuglink (elf, &word);
  if (!name)
    return -1;
  const char *mainfile = NULL;
  Dwarf_Addr  low = 0;
  const char *modname = dwfl_module_info (module, NULL, &low, NULL, NULL, NULL, &mainfile, NULL);
  int         fd = dwfl_standard_find_debuginfo (module, NULL, modname, low, mainfile, name, word, (char **)&data);
  if (fd <= 0)
    return -1;
  return fd;
}

// This function was written by me
int
__vala_rt_find_debug_altlink (Dwarf *dbg)
{
  const char *altname;
  const void *build_id;
  assert (dbg);
  ssize_t build_id_len = dwelf_dwarf_gnu_debugaltlink (dbg, &altname, &build_id);

  /* Couldn't even get the debugaltlink.  It probably doesn't exist.  */
  if (build_id_len <= 0)
    return -1;

  const uint8_t *id = (const uint8_t *)build_id;
  size_t         id_len = build_id_len;
  int            fd = -1;

  /* We only look in the standard path.  And relative to the dbg file.
     We don't handle very short or really large build-ids.  We need at
     at least 3 and allow for up to 64 (normally ids are 20 long).  */
#define MIN_BUILD_ID_BYTES 3
#define MAX_BUILD_ID_BYTES 64
  if (id_len >= MIN_BUILD_ID_BYTES && id_len <= MAX_BUILD_ID_BYTES)
    {
      /* Note sizeof a string literal includes the trailing zero.  */
      char id_path[sizeof DEBUGINFO_PATH - 1 + sizeof "/.build-id/" - 1 + 2 + 1 + (MAX_BUILD_ID_BYTES - 1) * 2
                   + sizeof ".debug"];
      sprintf (&id_path[0], "%s%s", DEBUGINFO_PATH, "/.build-id/");
      sprintf (&id_path[sizeof DEBUGINFO_PATH - 1 + sizeof "/.build-id/" - 1], "%02" PRIx8 "/", (uint8_t)id[0]);
      for (size_t i = 1; i < id_len; ++i)
        sprintf (&id_path[sizeof DEBUGINFO_PATH - 1 + sizeof "/.build-id/" - 1 + 3 + (i - 1) * 2],
                 "%02" PRIx8,
                 (uint8_t)id[i]);
      strcpy (&id_path[sizeof DEBUGINFO_PATH - 1 + sizeof "/.build-id/" - 1 + 3 + (id_len - 1) * 2], ".debug");
      fd = TEMP_FAILURE_RETRY (open (id_path, O_RDONLY));
    }

  /* Fall back on (possible relative) alt file path.  */
  if (fd < 0)
    {
      char *altpath = __vala_rt__libdw_filepath ((const char *)((uintptr_t)dbg) + sizeof (void *), NULL, altname);
      if (altpath != NULL)
        {
          fd = TEMP_FAILURE_RETRY (open (altpath, O_RDONLY));
          free (altpath);
        }
    }

  if (fd >= 0)
    {
      return fd;
    }
  return -1;
}
