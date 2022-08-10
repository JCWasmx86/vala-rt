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
#define LOCAL_VALA_DEBUG_PATH "/local/share/vala/debug/"
#define DBG_MAGIC "VDBG"
#define CURRENT_VERSION 1

struct linux_dirent
{
  unsigned long  d_ino;
  unsigned long  d_off;
  unsigned short d_reclen;
  char           d_name[];
};

static char __vala_rt_scratch_buffer[BUF_SIZE] = { 0 };

const char *
__vala_rt_load_from_rt (const char *, const char *, const char *);
const char *
__vala_rt_load_from_file (const char *, const char *);
const char *
__vala_rt_scan_directory (const char *, const char *);

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
      const char *r = __vala_rt_scan_directory (path, function);
      if (r)
        {
          return r;
        }
      memset (path, 0, BUF_SIZE);
      strcat (path, __vala_debug_prefix);
      strcat (path, LOCAL_VALA_DEBUG_PATH);
      r = __vala_rt_scan_directory (path, function);
      if (r)
        {
          return r;
        }
    }
  if (__vala_extra_debug_directories)
    {
      for (size_t i = 0; __vala_extra_debug_directories[i]; i++)
        {
          const char *demangled = __vala_rt_scan_directory (__vala_extra_debug_directories[i], function);
          if (demangled)
            {
              return demangled;
            }
        }
    }
  return NULL;
}

const char *
__vala_rt_scan_directory (const char *path, const char *function)
{
  int fd = open (path, O_RDONLY | O_DIRECTORY);
  if (fd == -1)
    {
      return NULL;
    }
  while (1)
    {
      char buf[BUF_SIZE];
      int  nread = syscall (SYS_getdents, fd, buf, BUF_SIZE);
      if (nread <= 0)
        {
          break;
        }
      for (long bpos = 0; bpos < nread;)
        {
          struct linux_dirent *d = (struct linux_dirent *)(buf + bpos);
          char                 d_type = *(buf + bpos + d->d_reclen - 1);
          size_t               len = strlen (d->d_name);
          size_t               extension_len = strlen (".vdbg");
          if (d_type == DT_REG && len >= extension_len
              && memcmp (&d->d_name[len - extension_len], ".vdbg", extension_len) == 0)
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
  char   magic[strlen (DBG_MAGIC)];
  size_t nread = read (fd, magic, sizeof (magic));
  if (nread != sizeof (magic))
    {
      goto end;
    }
  if (memcmp (magic, DBG_MAGIC, strlen (DBG_MAGIC)))
    {
      goto end;
    }
  uint8_t version;
  nread = read (fd, &version, sizeof (version));
  if (nread != sizeof (version))
    {
      goto end;
    }
  if (version != CURRENT_VERSION)
    {
      goto end;
    }
  uint32_t n_functions;
  nread = read (fd, &n_functions, sizeof (n_functions));
  n_functions = __bswap_constant_32 (n_functions);
  if (nread != sizeof (n_functions))
    {
      goto end;
    }
  for (uint32_t i = 0; i < n_functions; i++)
    {
      uint16_t len = 0;
      nread = read (fd, &len, sizeof (len));
      len = __bswap_constant_16 (len);
      if (nread != sizeof (len))
        {
          goto end;
        }
      char c_name[len + 1];
      memset (c_name, 0, len + 1);
      nread = read (fd, c_name, len + 1);
      if (nread != (size_t)len + 1)
        {
          goto end;
        }
      if (c_name[len])
        {
          goto end;
        }
      len = 0;
      nread = read (fd, &len, sizeof (len));
      len = __bswap_constant_16 (len);
      if (nread != sizeof (len))
        {
          goto end;
        }
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
      if (nread != (size_t)len + 1)
        {
          goto end;
        }
      if (function_name[len])
        {
          goto end;
        }
    }
end:
  close (fd);
  return NULL;
}
