#include "vala-rt-internal.h"
#include "vala-rt.h"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

static struct vala_mappings *__bdirect_mappings = NULL;

const char *
__vala_rt_find_function_internal (const char *str)
{
  if (!__bdirect_mappings)
    {
      __bdirect_mappings = dlsym (RTLD_DEFAULT, "__vala_mappings");
      if (!__bdirect_mappings)
        return str;
    }
  for (size_t i = 0; __bdirect_mappings[i].function_name != NULL; i++)
    {
      if (!strcmp (str, __bdirect_mappings[i].function_name))
        {
          return __bdirect_mappings[i].demangled;
        }
    }
  return NULL;
}
