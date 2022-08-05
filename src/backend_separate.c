#include "vala-rt-internal.h"
#include "vala-rt.h"
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#define BUF_SIZE 1024
#define VALA_DEBUG_PATH "/share/vala/debug/"

struct linux_dirent
{
  unsigned long  d_ino;
  unsigned long  d_off;
  unsigned short d_reclen;
  char           d_name[];
};

static char __vala_rt_scratch_buffer[BUF_SIZE] = { 0 };

const char *
__vala_rt_load_from_rt (const char *prefix, const char *file, const char *function);

const char *
__vala_rt_load_from_file (const char *file, const char *function);

const char *
__vala_rt_find_function_internal_file (const char *function)
{
  errno = 0;
  if (__vala_debug_prefix)
    {
      // For each vdbg
      char path[BUF_SIZE] = { 0 };
      strcat (path, __vala_debug_prefix);
      strcat (path, VALA_DEBUG_PATH);
      int fd = open (path, O_RDONLY | O_DIRECTORY);
      if (fd == -1)
        {
          perror ("open");
          goto next_try;
        }
      while (1)
        {
          char buf[BUF_SIZE];
          int  nread = syscall (SYS_getdents, fd, buf, BUF_SIZE);
          if (nread <= 0)
            break;
          for (long bpos = 0; bpos < nread;)
            {
              struct linux_dirent *d = (struct linux_dirent *)(buf + bpos);
              char                 d_type = *(buf + bpos + d->d_reclen - 1);
              size_t               len = strlen (d->d_name);
              if (d_type == DT_REG && len >= 5 && memcmp (&d->d_name[len - 5], ".vdbg", 5) == 0)
                {
                  const char *demangled = __vala_rt_load_from_rt (path, d->d_name, function);
                  if (demangled)
                    {
                      close (fd);
                      return demangled;
                    }
                }
              bpos += d->d_reclen;
            }
        }
      close (fd);
    }
next_try:
  if (__vala_extra_debug_files)
    {
      for (size_t i = 0; __vala_extra_debug_files[i]; i++)
        {
          const char *demangled = __vala_rt_load_from_file (__vala_extra_debug_files[i], function);
          if (demangled)
            return demangled;
        }
    }
  return NULL;
}

const char *
__vala_rt_load_from_rt (const char *prefix, const char *file, const char *function)
{
  char full_filename[strlen (file) + strlen (prefix) + 2];
  memset (full_filename, 0, sizeof (full_filename));
  memcpy (full_filename, prefix, strlen (prefix));
  full_filename[strlen (prefix)] = '/';
  memcpy (&full_filename[strlen (prefix) + 1], file, strlen (file));
  return __vala_rt_load_from_file (full_filename, function);
}

const char *
__vala_rt_load_from_file (const char *file, const char *function)
{
  int fd = open (file, O_RDONLY);
  if (fd <= 0)
    {
      perror ("open");
      return NULL;
    }
  char    magic[4];
  ssize_t nread = read (fd, magic, 4);
  if (nread != 4)
    goto end;
  if (memcmp (magic, "VDBG", 4))
    goto end;
  uint8_t version;
  nread = read (fd, &version, sizeof (version));
  if (nread != 1)
    goto end;
  if (version != 1)
    goto end;
  uint32_t n_functions;
  nread = read (fd, &n_functions, sizeof (n_functions));
  n_functions = __bswap_constant_32 (n_functions);
  if (nread != 4)
    goto end;
  for (uint32_t i = 0; i < n_functions; i++)
    {
      uint16_t len = 0;
      nread = read (fd, &len, sizeof (len));
      len = __bswap_constant_16 (len);
      if (nread != sizeof (len))
        goto end;
      char c_name[len + 1];
      memset (c_name, 0, len + 1);
      nread = read (fd, c_name, len + 1);
      if (nread != len + 1)
        goto end;
      if (c_name[len])
        goto end;
      len = 0;
      nread = read (fd, &len, sizeof (len));
      len = __bswap_constant_16 (len);
      if (nread != 2)
        goto end;
      char function_name[len + 1];
      memset (function_name, 0, len + 1);
      nread = read (fd, function_name, len + 1);
      int matches = strcmp (function, c_name) == 0;
      if (matches)
        {
          memset (__vala_rt_scratch_buffer, 0, BUF_SIZE);
          memcpy (__vala_rt_scratch_buffer, function_name, len);
          close (fd);
          return __vala_rt_scratch_buffer;
        }
      size_t f_len = strlen (function);
      if (strlen (c_name) < f_len && memcmp (c_name, function, strlen (c_name)) == 0
          && function[strlen (c_name)] == '.')
        {
          memset (__vala_rt_scratch_buffer, 0, BUF_SIZE);
          memcpy (__vala_rt_scratch_buffer, function_name, len);
          close (fd);
          return __vala_rt_scratch_buffer;
        }
      if (nread != len + 1)
        goto end;
      if (function_name[len])
        goto end;
    }
end:
  close (fd);
  return NULL;
}
