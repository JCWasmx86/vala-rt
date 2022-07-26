/* vala-rt.c
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
#define UNW_LOCAL_ONLY

#include "vala-rt.h"
#include <elfutils/libdwfl.h>
#include <libunwind.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
__vala_rt_handle_signal (int signum);

static int                         __vala_rt_handler_triggered = 0;
static size_t                      __vala_rt_n_mappings = 0;
static const struct vala_mappings *__vala_rt_mappings = NULL;

void
__vala_init_handlers (__attribute__ ((unused)) char **argv, const struct vala_mappings *mappings, size_t n_mappings)
{
  signal (SIGSEGV, __vala_rt_handle_signal);
  signal (SIGABRT, __vala_rt_handle_signal);
  __vala_rt_mappings = mappings;
  __vala_rt_n_mappings = n_mappings;
}

static void
write_frame (int frame)
{
  char data[20] = { 0 };
  int  n = snprintf (data, 20, "#%d", frame);
  write (STDERR_FILENO, data, n);
  for (int i = n; i < 5; i++)
    write (STDERR_FILENO, " ", 1);
}

static void
write_good_backtrace (const char *modulename, const char *mangled, const char *filename, int line)
{
  size_t len = strlen (mangled);
  write (STDERR_FILENO, mangled, len);
  for (size_t i = len; i <= 50; i++)
    write (STDERR_FILENO, " ", 1);
  write (STDERR_FILENO, " at ", 4);
  len = strlen (filename);
  size_t sum = len;
  write (STDERR_FILENO, filename, len);
  char data[20] = { 0 };
  len = snprintf (data, 20, ":%d", line);
  sum += len;
  write (STDERR_FILENO, data, len);
  for (size_t i = sum; i <= 50; i++)
    write (STDERR_FILENO, " ", 1);
  write (STDERR_FILENO, " in ", 4);
  write (STDERR_FILENO, modulename, strlen (modulename));
  write (STDERR_FILENO, "\n", 1);
}

static void
__vala_rt_handle_signal (int signum)
{
  if (__vala_rt_handler_triggered)
    return;
  psignal (signum, "Received signal");
  __vala_rt_handler_triggered = 1;
  unw_context_t uc = { 0 };
  unw_getcontext (&uc);
  unw_cursor_t cursor = { 0 };
  unw_init_local (&cursor, &uc);
  unw_step (&cursor);
  Dwfl *dwfl = NULL;
  // This uses so much malloc, but what can
  // it do at this point?
  int frame = 0;
  while (unw_step (&cursor) > 0)
    {
      unw_word_t ip;
      unw_get_reg (&cursor, UNW_REG_IP, &ip);
      unw_word_t     offset;
      char           name[128];
      char          *debuginfo_path = NULL;
      Dwfl_Callbacks callbacks = {
        .find_elf = dwfl_linux_proc_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo,
        .debuginfo_path = &debuginfo_path,
      };

      unw_get_proc_name (&cursor, name, sizeof (name), &offset);

      dwfl = dwfl_begin (&callbacks);
      dwfl_linux_proc_report (dwfl, getpid ());
      dwfl_report_end (dwfl, NULL, NULL);
      Dwarf_Addr   addr = (uintptr_t)ip;
      Dwfl_Module *module = dwfl_addrmodule (dwfl, addr);
      const char  *function_name = dwfl_module_addrname (module, addr);
      const char  *real_name = function_name;
      for (size_t i = 0; i < __vala_rt_n_mappings && function_name; i++)
        {
          if (!strcmp (__vala_rt_mappings[i].function_name, function_name))
            {
              real_name = __vala_rt_mappings[i].demangled;
              break;
            }
        }
      Dwfl_Line  *line = dwfl_getsrc (dwfl, addr);
      const char *module_name = dwfl_module_info (module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      write_frame (frame);
      if (line && real_name)
        {
          int         nline;
          Dwarf_Addr  addr;
          const char *filename = dwfl_lineinfo (line, &addr, &nline, NULL, NULL, NULL);
          write_good_backtrace (module_name, real_name, filename, nline);
        }
      else
        {
          char data[1024] = { 0 };
          int  n = snprintf (data, 1024, "<%p> in %s\n", (void *)ip, module_name);
          write (STDERR_FILENO, data, n);
        }
      if (function_name && (!strcmp ("_vala_main", function_name) || !strcmp ("__libc_start_call_main", function_name)))
        break;
      dwfl_end (dwfl);
      frame++;
      fsync (STDERR_FILENO);
    }
  dwfl_end (dwfl);
  fsync (STDERR_FILENO);
  abort ();
}
