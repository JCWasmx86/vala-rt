#include "vala-rt-internal.h"
#include "vala-rt.h"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MAGIC_HEADER "VALA_DEBUG_INFO1"

const char *
__vala_rt_find_function_internal_section (const char *function_name, const void *data, size_t len)
{
  const uint8_t *section = data;
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
            goto end;
          memcpy (&num_mappings, &section[offset], 8);
          num_mappings = __builtin_bswap64 (num_mappings);
          offset += 8;
          for (uint64_t j = 0; j < num_mappings; j++)
            {
              if (offset == len)
                goto end;
              uint8_t len_c_name = section[offset];
              offset++;
              if (offset == len || offset + len_c_name >= len)
                goto end;
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
