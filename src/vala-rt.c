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
#define _GNU_SOURCE

#include "vala-rt.h"
#include "vala-rt-internal.h"
#include <dlfcn.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <libunwind.h>
#include <linux/limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SIGNAL_MAPPINGS 150
#define MAX_BACKTRACE_DEPTH 150
#define MAX(a, b) (a > b ? a : b)

static void
__vala_rt_handle_signal (int, siginfo_t *, void *);
static void
__vala_rt_add_handler (int);
static const char *
__vala_rt_find_function (const char *, unw_cursor_t *, void *, size_t, int);
static const char *
__vala_rt_find_signal (const char *, const char *);
static void
__vala_rt_format_signal_name (char *, const char *);
static void
__vala_rt_find_section_in_elf (Elf *, const char *, void **, size_t *);
static int
__vala_rt_find_debuginfo_by_id (Dwfl_Module *);

struct mapping_holder
{
  char                              *library_path;
  const struct vala_signal_mappings *mappings;
  size_t                             n_mappings;
};

struct stack_frame
{
  char       function_name[128];
  char       library_name[256];
  char       filename[256];
  int        lineno;
  unw_word_t ip;
  int        skip : 2;
};

struct mapping_holder     __vala_rt_signal_mappings[MAX_SIGNAL_MAPPINGS];
size_t                    __vala_rt_n_signal_mappings = 0;
static struct stack_frame __vala_rt_saved_stackframes[MAX_BACKTRACE_DEPTH];
static int                __vala_rt_n_saved_stackframes;
static int                __vala_rt_handler_triggered = 0;
static int                __vala_rt_already_initialized = 0;
static char               __vala_rt_debuginfod_location1[256] = { 0 };
static char               __vala_rt_debuginfod_location2[256] = { 0 };

void
__vala_init (void)
{
  if (__vala_rt_already_initialized)
    {
      return;
    }
  __vala_rt_already_initialized = 1;
  __vala_rt_add_handler (SIGSEGV);
  __vala_rt_add_handler (SIGILL);
  __vala_rt_add_handler (SIGFPE);
  __vala_rt_add_handler (SIGABRT);
  if (getenv ("XDG_CACHE_HOME"))
    {
      snprintf ((char *)__vala_rt_debuginfod_location1, 255, "%s/debuginfod_client/", getenv ("XDG_CACHE_HOME"));
    }
  const char *homedir;

  if ((homedir = getenv ("HOME")) == NULL)
    {
      homedir = getpwuid (getuid ())->pw_dir;
    }
  snprintf ((char *)__vala_rt_debuginfod_location2, 255, "%s/.cache/debuginfod_client/", homedir);
}

static void
__vala_rt_add_handler (int signum)
{
  struct sigaction action;
  memset (&action, 0, sizeof action);
  action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND;
  sigfillset (&action.sa_mask);
  sigdelset (&action.sa_mask, signum);
  action.sa_sigaction = __vala_rt_handle_signal;
  sigaction (signum, &action, NULL);
}

static void
print_initial_part (int curr, unw_word_t ip, int max)
{
  char data[128] = { 0 };
  if (max > 100)
    {
      if (curr < 10)
        {
          sprintf (data, "#%d   ", curr);
        }
      else if (curr < 100)
        {
          sprintf (data, "#%d  ", curr);
        }
      else
        {
          sprintf (data, "#%d ", curr);
        }
    }
  else if (max > 10)
    {
      if (curr < 10)
        {
          sprintf (data, "#%d  ", curr);
        }
      else
        {
          sprintf (data, "#%d ", curr);
        }
    }
  else
    {
      sprintf (data, "#%d ", curr);
    }
  write (STDERR_FILENO, data, strlen (data));
  memset (data, 0, sizeof (data));
  sprintf (data, "<0x%016lx> ", (uint64_t)ip);
  write (STDERR_FILENO, data, strlen (data));
}

static void
pad_string (const char *s, size_t len)
{
  write (STDERR_FILENO, s, strlen (s));
  for (size_t i = strlen (s); i <= len; i++)
    {
      write (STDERR_FILENO, " ", 1);
    }
}

static void
__vala_rt_handle_signal (int signum, __attribute__ ((unused)) siginfo_t *info, __attribute__ ((unused)) void *_ctx)
{
  if (__vala_rt_handler_triggered)
    {
      return;
    }
  __vala_rt_n_saved_stackframes = 0;
  memset (__vala_rt_saved_stackframes, 0, sizeof (__vala_rt_saved_stackframes));
  psignal (signum, "Received signal");
  __vala_rt_handler_triggered = 1;
  unw_context_t uc = { 0 };
  unw_getcontext (&uc);
  unw_cursor_t cursor = { 0 };
#ifdef UNW_INIT_SIGNAL_FRAME
  unw_init_local2 (&cursor, &uc, UNW_INIT_SIGNAL_FRAME);
#else
  unw_init_local (&cursor, &uc);
#endif
  unw_step (&cursor);
  Dwfl *dwfl = NULL;
  // This uses so much malloc, but what can
  // it do at this point?
  int frame = 0;
  while (unw_step (&cursor) > 0 && __vala_rt_n_saved_stackframes < MAX_BACKTRACE_DEPTH)
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
      Dwarf_Addr   ipaddr = (uintptr_t)ip;
      Dwfl_Module *module = dwfl_addrmodule (dwfl, ipaddr);
      GElf_Addr    gaddr = 0;
      Elf         *elf = dwfl_module_getelf (module, &gaddr);
      Dwarf_Addr   bias;
      Dwarf       *dwarf = dwfl_module_getdwarf (module, &bias);
      Dwarf       *alt_dwarf = dwarf_getalt (dwarf);
      void        *section_data = NULL;
      size_t       section_size = 0;
      Elf         *second_elf = NULL;
      int          compressed = 0;
      __vala_rt_find_section_in_elf (elf, ".debug_info_vala", &section_data, &section_size);
      if (!section_data)
        {
          __vala_rt_find_section_in_elf (elf, ".zdebug_info_vala", &section_data, &section_size);
          if (section_data)
            {
              compressed = 1;
            }
        }
      if (!section_data && alt_dwarf)
        {
          elf = dwarf_getelf (alt_dwarf);
          __vala_rt_find_section_in_elf (elf, ".debug_info_vala", &section_data, &section_size);
          if (!section_data)
            {
              __vala_rt_find_section_in_elf (elf, ".zdebug_info_vala", &section_data, &section_size);
              if (section_data)
                {
                  compressed = 1;
                }
            }
        }
      if (!section_data)
        {
          int fd = __vala_rt_find_debuginfo_by_id (module);
          if (fd > 0)
            {
              second_elf = elf_begin (fd, ELF_C_READ, NULL);
              __vala_rt_find_section_in_elf (second_elf, ".debug_info_vala", &section_data, &section_size);
              if (!section_data)
                {
                  __vala_rt_find_section_in_elf (second_elf, ".zdebug_info_vala", &section_data, &section_size);
                  if (section_data)
                    {
                      compressed = 1;
                    }
                }
            }
        }
      __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].ip = ip;
      __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].skip = 0;
      const char *function_name = dwfl_module_addrname (module, ipaddr);
      const char *real_name = __vala_rt_find_function (function_name, &cursor, section_data, section_size, compressed);
      if (real_name)
        {
          strcpy (__vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].function_name, real_name);
        }
      else
        {
          __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].function_name[0] = 1;
        }
      Dwfl_Line  *line = dwfl_getsrc (dwfl, ipaddr);
      const char *module_name = dwfl_module_info (module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      strcpy (__vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].library_name, module_name);
      if (line && real_name)
        {
          int         nline;
          Dwarf_Addr  addr;
          const char *filename = dwfl_lineinfo (line, &addr, &nline, NULL, NULL, NULL);
          strcpy (__vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].filename, filename);
          __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].lineno = nline;
        }
      else
        {
          __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].filename[0] = (char)1;
          __vala_rt_saved_stackframes[__vala_rt_n_saved_stackframes].lineno = -1;
        }
      __vala_rt_n_saved_stackframes++;
      if (second_elf)
        {
          elf_end (second_elf);
        }
      // TODO: Match _vala_main.constprop.0
      if (function_name && (!strcmp ("_vala_main", function_name) || !strcmp ("__libc_start_call_main", function_name)))
        {
          break;
        }
      dwfl_end (dwfl);
      frame++;
    }
  dwfl_end (dwfl);
  // Search for call stacks like this:
  // __lambda4_              | May be inlined
  // ___lambda4_class_signal
  // GLib::Closure.invoke
  // signal_emit_unlocked_R
  // g_signal_emit_valist
  // GLib::Signal.emit
  // And replace them by this:
  // __lambda4_ or ___lambda4_class_signal
  // <<signal Class::signal>>
  for (int i = 0; i < __vala_rt_n_saved_stackframes; i++)
    {
      if (!__vala_rt_find_signal (__vala_rt_saved_stackframes[i].library_name,
                                  __vala_rt_saved_stackframes[i].function_name))
        {
          continue;
        }
      if (__vala_rt_saved_stackframes[i].function_name[0] == 1)
        {
          continue;
        }
      if (strcmp (__vala_rt_saved_stackframes[i].library_name, __vala_rt_saved_stackframes[i + 1].library_name) == 0)
        {
          const char *s1 = __vala_rt_find_signal (__vala_rt_saved_stackframes[i].library_name,
                                                  __vala_rt_saved_stackframes[i].function_name);
          const char *s2 = __vala_rt_find_signal (__vala_rt_saved_stackframes[i + 1].library_name,
                                                  __vala_rt_saved_stackframes[i + 1].function_name);
          // TODO: Can we compare addresses here?
          if (s1 && s2 && !strcmp (s1, s2))
            {
              if ((strcmp (__vala_rt_saved_stackframes[i + 2].function_name, "GLib::Closure.invoke") == 0
                   || strcmp (__vala_rt_saved_stackframes[i + 2].function_name, "g_closure_invoke") == 0)
                  && strncmp (__vala_rt_saved_stackframes[i + 3].function_name, "signal_emit_unlocked_R", 22) == 0)
                {
                  int n_to_skip = 2;
                  if (i + 4 < __vala_rt_n_saved_stackframes
                      && strcmp (__vala_rt_saved_stackframes[i + 4].function_name, "g_signal_emitv") == 0)
                    {
                      n_to_skip++;
                    }
                  else if (i + 4 < __vala_rt_n_saved_stackframes
                           && strcmp (__vala_rt_saved_stackframes[i + 4].function_name, "g_signal_emit_valist") == 0)
                    {
                      n_to_skip++;
                      if (i + 5 < __vala_rt_n_saved_stackframes
                          && strcmp (__vala_rt_saved_stackframes[i + 5].function_name, "g_signal_emit") == 0)
                        {
                          n_to_skip++;
                        }
                      if (i + 5 < __vala_rt_n_saved_stackframes
                          && strcmp (__vala_rt_saved_stackframes[i + 5].function_name, "g_signal_emit_by_name") == 0)
                        {
                          n_to_skip++;
                        }
                    }
                  if (s1)
                    {
                      __vala_rt_format_signal_name (__vala_rt_saved_stackframes[i + 1].function_name, s1);
                      for (int j = 1; j < n_to_skip + 1; j++)
                        {
                          __vala_rt_saved_stackframes[i + 1 + j].skip = 1;
                        }
                      i += n_to_skip;
                    }
                }
            }
        }
      else if (i + 2 < __vala_rt_n_saved_stackframes)
        {
          if ((strcmp (__vala_rt_saved_stackframes[i + 1].function_name, "GLib::Closure.invoke") == 0
               || strcmp (__vala_rt_saved_stackframes[i + 1].function_name, "g_closure_invoke") == 0)
              && strncmp (__vala_rt_saved_stackframes[i + 2].function_name, "signal_emit_unlocked_R", 22) == 0)
            {
              int n_to_skip = 1;
              if (i + 3 < __vala_rt_n_saved_stackframes
                  && strcmp (__vala_rt_saved_stackframes[i + 3].function_name, "g_signal_emitv") == 0)
                {
                  n_to_skip++;
                }
              else if (i + 3 < __vala_rt_n_saved_stackframes
                       && strcmp (__vala_rt_saved_stackframes[i + 3].function_name, "g_signal_emit_valist") == 0)
                {
                  n_to_skip++;
                  if (i + 4 < __vala_rt_n_saved_stackframes
                      && strcmp (__vala_rt_saved_stackframes[i + 4].function_name, "g_signal_emit") == 0)
                    {
                      n_to_skip++;
                    }
                  if (i + 4 < __vala_rt_n_saved_stackframes
                      && strcmp (__vala_rt_saved_stackframes[i + 4].function_name, "g_signal_emit_by_name") == 0)
                    {
                      n_to_skip++;
                    }
                }
              const char *s = __vala_rt_find_signal (__vala_rt_saved_stackframes[i].library_name,
                                                     __vala_rt_saved_stackframes[i].function_name);
              if (s)
                {
                  __vala_rt_format_signal_name (__vala_rt_saved_stackframes[i + 1].function_name, s);
                  for (int j = 2; j < n_to_skip + 2; j++)
                    {
                      __vala_rt_saved_stackframes[i + j].skip = 1;
                    }
                  i += n_to_skip;
                }
            }
        }
    }
  size_t n_traces = 0;
  size_t max_fname = 0;
  size_t max_filename = 0;
  size_t max_lname = 0;
  for (int i = 0; i < __vala_rt_n_saved_stackframes; i++)
    {
      if (!__vala_rt_saved_stackframes[i].skip)
        {
          n_traces++;
          max_fname = MAX (max_fname, strlen (__vala_rt_saved_stackframes[i].function_name));
          max_lname = MAX (max_lname, strlen (__vala_rt_saved_stackframes[i].library_name));
          max_filename = MAX (max_filename, strlen (__vala_rt_saved_stackframes[i].filename));
        }
    }
  int cnter = 0;
  for (int i = 0; i < __vala_rt_n_saved_stackframes; i++)
    {
      if (!__vala_rt_saved_stackframes[i].skip)
        {
          print_initial_part (cnter, __vala_rt_saved_stackframes[i].ip, n_traces);
          pad_string (__vala_rt_saved_stackframes[i].library_name, max_lname);
          if (__vala_rt_saved_stackframes[i].function_name[0] == 1)
            {
              goto eol;
            }
          pad_string (__vala_rt_saved_stackframes[i].function_name, max_fname);
          if (__vala_rt_saved_stackframes[i].filename[0] == 1)
            {
              goto eol;
            }
          write (
              STDERR_FILENO, __vala_rt_saved_stackframes[i].filename, strlen (__vala_rt_saved_stackframes[i].filename));
          if (__vala_rt_saved_stackframes[i].lineno == -1)
            {
              goto eol;
            }
          write (STDERR_FILENO, ":", 1);
          char data[10] = { 0 };
          sprintf (data, "%d", __vala_rt_saved_stackframes[i].lineno);
          write (STDERR_FILENO, data, strlen (data));
        eol:
          write (STDERR_FILENO, "\n", 1);
          cnter++;
        }
    }
  abort ();
}

static const char *
__vala_rt_find_function (const char                            *function,
                         __attribute__ ((unused)) unw_cursor_t *cursor,
                         void                                  *data,
                         size_t                                 len,
                         int                                    compressed)
{
  if (function == NULL)
    {
      return NULL;
    }
  if (function[0] == '<')
    {
      return function;
    }

  if (strncmp (function, "_vala_main.constprop.", strlen ("_vala_main.constprop.")) == 0)
    {
      return "main";
    }
  const char *r = __vala_rt_find_function_internal_file (function);
  if (r)
    {
      return r;
    }
  if (data && len)
    {
      const char *r1 = __vala_rt_find_function_internal_section (function, data, len, compressed);
      if (r1)
        {
          return r1;
        }
    }
  return function;
}

static const char *
__vala_rt_find_signal (const char *library, const char *function_name)
{
  char real_path_tmp[PATH_MAX + 1] = { 0 };
  for (size_t i = 0; i < __vala_rt_n_signal_mappings; i++)
    {
      realpath (library, real_path_tmp);
      if (!strcmp (__vala_rt_signal_mappings[i].library_path, library)
          || !strcmp (__vala_rt_signal_mappings[i].library_path, real_path_tmp))
        {
          for (size_t j = 0; j < __vala_rt_signal_mappings[i].n_mappings; j++)
            {
              if (!strcmp (__vala_rt_signal_mappings[i].mappings[j].c_function_name, function_name))
                {
                  return __vala_rt_signal_mappings[i].mappings[j].demangled_signal_name;
                }
            }
        }
    }
  return NULL;
}

void
__vala_register_signal_mappings (const char                        *library_path,
                                 const struct vala_signal_mappings *mappings,
                                 size_t                             n_mappings)
{
  if (__vala_rt_n_signal_mappings == MAX_SIGNAL_MAPPINGS)
    {
      fprintf (stderr, "Unable to register vala signal mappings for %s\n", library_path);
      return;
    }
  __vala_rt_signal_mappings[__vala_rt_n_signal_mappings].library_path = strdup (library_path);
  __vala_rt_signal_mappings[__vala_rt_n_signal_mappings].n_mappings = n_mappings;
  __vala_rt_signal_mappings[__vala_rt_n_signal_mappings].mappings = mappings;
  __vala_rt_n_signal_mappings++;
}

static void
__vala_rt_format_signal_name (char *into, const char *demangled)
{
  memset (into, 0, strlen (into));
  strcat (into, "<<signal ");
  strcat (into, demangled);
  strcat (into, ">>");
}

static void
__vala_rt_find_section_in_elf (Elf *elf, const char *sname, void **ptr, size_t *len)
{
  size_t num_sections = 0;
  elf_getshdrnum (elf, &num_sections);
  size_t shstrndx;
  elf_getshdrstrndx (elf, &shstrndx);
  for (size_t i = 0; i < num_sections; i++)
    {
      Elf_Scn  *scn = elf_getscn (elf, i);
      GElf_Shdr shdr;
      gelf_getshdr (scn, &shdr);
      const char *name = elf_strptr (elf, shstrndx, shdr.sh_name);
      if (!strcmp (sname, name))
        {
          Elf_Data *data = NULL;
          data = elf_rawdata (scn, data);
          *ptr = data->d_buf;
          *len = data->d_size;
          return;
        }
    }
}
// Last resort, guessing and hoping the best
static int
__vala_rt_find_debuginfo_by_id (Dwfl_Module *module)
{
  unsigned char bits[32] = { 0 };
  GElf_Addr     addr = 0;
  dwfl_module_getelf (module, &addr);
  int ret = dwfl_module_build_id (module, (const unsigned char **)&bits, &addr);
  if (ret <= 0)
    {
      return -1;
    }
  uint8_t    *id = (uint8_t *)addr;
  char        path[512];
  const char *prefixes_to_try[6]
      = { "/usr/lib/debug/.build-id/",       "/usr/local/lib/debug/.build-id/", "/app/lib/debug/.build-id/",
          "/app/local/lib/debug/.build-id/", __vala_rt_debuginfod_location1,    __vala_rt_debuginfod_location2 };

  for (size_t i = 0; i < sizeof (prefixes_to_try) / sizeof (prefixes_to_try[0]); i++)
    {
      if (!prefixes_to_try[i][0])
        {
          continue;
        }
      memset (path, 0, sizeof (path));
      strcat (path, prefixes_to_try[i]);
      size_t base_len = strlen (path);
      sprintf (&path[base_len], "%x%x/", id[0] >> 4 & 0xf, id[0] & 0xf);
      base_len += 3;
      for (int j = 1; j < ret; j++)
        {
          sprintf (&path[base_len], "%x%x", id[j] >> 4 & 0xf, id[j] & 0xf);
          base_len += 2;
        }
      strcat (path, ".debug");
      int fd = open (path, O_RDONLY);
      if (fd < 0)
        {
          continue;
        }
      return fd;
    }
  return -1;
}
