#include "vala-rt-internal.h"
#include "vala-rt.h"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#define MAGIC_HEADER "VALA_DEBUG_INFO1"
#define BUF_SIZE 1024

static char __vala_rt_section_scratch_buffer[BUF_SIZE] = { 0 };

const char *
__vala_rt_find_function_internal_section_compressed (const char *, const void *, size_t);

const char *
__vala_rt_find_function_internal_section (const char *function_name, const void *data, size_t len, int compressed)
{
  const uint8_t *section = data;
  if (compressed)
    {
      return __vala_rt_find_function_internal_section_compressed (function_name, data, len);
    }
  for (size_t i = 0; i < len; i++)
    {
      if (i + strlen (MAGIC_HEADER) < len && memcmp (&section[i], MAGIC_HEADER, strlen (MAGIC_HEADER)) == 0)
        {
          uint64_t num_mappings = 0;
          size_t   offset = i + strlen (MAGIC_HEADER);
          uint64_t version = 0;
          memcpy (&version, &section[offset], 8);
          offset += 8;
          if (version != 1)
            {
              goto end;
            }
          memcpy (&num_mappings, &section[offset], 8);
          num_mappings = __builtin_bswap64 (num_mappings);
          offset += 8;
          for (uint64_t j = 0; j < num_mappings; j++)
            {
              if (offset == len)
                {
                  goto end;
                }
              uint8_t len_c_name = section[offset];
              offset++;
              if (offset == len || offset + len_c_name >= len)
                {
                  goto end;
                }
              if (strcmp ((const char *)&section[offset], function_name) == 0)
                {
                  offset += len_c_name + 2;
                  // Skip length of variable
                  offset++;
                  return (const char *)&section[offset];
                }
              offset += len_c_name + 2;
              uint8_t len_mangled_name = section[offset];
              offset += len_mangled_name + 2;
              offset++;
            }
        }
    }
end:
  return NULL;
}

static int
__vala_rt_z_read (z_stream *strm, void *ptr, size_t len)
{
  strm->avail_out = len;
  strm->next_out = ptr;
  return inflate (strm, Z_NO_FLUSH);
}

const char *
__vala_rt_find_function_internal_section_compressed (const char *function_name, const void *data, size_t len)
{
  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  int ret = inflateInit (&strm);
  if (ret != Z_OK)
    {
      return NULL;
    }
  strm.avail_in = len - 12;
  strm.next_in = (Bytef *)data + 12;
  char magic[strlen (MAGIC_HEADER) + 1];
  magic[strlen (MAGIC_HEADER)] = 0;
  int status = __vala_rt_z_read (&strm, magic, strlen (MAGIC_HEADER));
  if (status != Z_OK)
    {
      goto end;
    }
  if (memcmp (magic, MAGIC_HEADER, strlen (MAGIC_HEADER)))
    {
      goto end;
    }
  uint64_t version = 0;
  status = __vala_rt_z_read (&strm, &version, sizeof (version));
  if (status != Z_OK)
    {
      goto end;
    }
  if (version != 1)
    {
      goto end;
    }
  uint64_t n_mappings = 0;
  status = __vala_rt_z_read (&strm, &n_mappings, sizeof (n_mappings));
  if (status != Z_OK)
    {
      goto end;
    }
  for (uint64_t i = 0; i < n_mappings; i++)
    {
      uint8_t cname_len = 0;
      status = __vala_rt_z_read (&strm, &cname_len, sizeof (cname_len));
      if (status != Z_OK)
        {
          goto end;
        }
      char cname[cname_len + 3];
      memset (cname, 0, cname_len + 3);
      status = __vala_rt_z_read (&strm, cname, cname_len + 2);
      if (status != Z_OK)
        {
          goto end;
        }
      uint8_t fname_len = 0;
      status = __vala_rt_z_read (&strm, &fname_len, sizeof (fname_len));
      if (status != Z_OK)
        {
          goto end;
        }
      char fname[fname_len + 3];
      memset (fname, 0, fname_len + 3);
      status = __vala_rt_z_read (&strm, fname, fname_len + 2);
      if (strcmp (cname, function_name) == 0)
        {
          memset (__vala_rt_section_scratch_buffer, 0, BUF_SIZE);
          memcpy (__vala_rt_section_scratch_buffer, fname, strlen (fname));
          inflateEnd (&strm);
          return __vala_rt_section_scratch_buffer;
        }
      if (status != Z_OK)
        {
          goto end;
        }
    }
end:
  inflateEnd (&strm);
  return NULL;
}
