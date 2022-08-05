#define _GNU_SOURCE
#include "vala-rt-internal.h"
#include "vala-rt.h"
#include <dlfcn.h>
#include <string.h>

static struct vala_mappings *__vala_rt__bdirect_mappings = NULL;

const char *
__vala_rt_find_function_internal_direct (const char *str)
{
  if (!__vala_rt__bdirect_mappings)
    {
      __vala_rt__bdirect_mappings = dlsym (RTLD_DEFAULT, "__vala_mappings");
      if (!__vala_rt__bdirect_mappings)
        return NULL;
    }
  for (size_t i = 0; __vala_rt__bdirect_mappings[i].function_name != NULL; i++)
    {
      if (!strcmp (str, __vala_rt__bdirect_mappings[i].function_name))
        {
          return __vala_rt__bdirect_mappings[i].demangled;
        }
    }
  return NULL;
}
