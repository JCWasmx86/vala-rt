#define _GNU_SOURCE
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <stddef.h>
#pragma once

const char *
__vala_rt_find_function_internal_file (const char *);
const char *
__vala_rt_find_function_internal_section (const char *, const void *, size_t, int);
