/* vala-rt.h
 *
 * Copyright 2022 JCWasmx86
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>

#pragma once

#define VALA_RT_INSIDE
#include "vala_rt-version.h"
#undef VALA_RT_INSIDE

struct vala_signal_mappings
{
  const char c_function_name[255];
  const char demangled_signal_name[255];
};

extern const char  *__vala_debug_prefix;
extern const char **__vala_extra_debug_directories;

extern void
__vala_init (void);
extern void
__vala_register_signal_mappings (const char *, const struct vala_signal_mappings *, size_t);
