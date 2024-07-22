// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2022 Ryan Castellucci
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <linux/limits.h>

#include "digestlist.h"
#include "bnprintf.h"

static int fill_template(char *d, size_t n, const char *template, const uint8_t *hash, size_t hashlen) {
  const char *esc, *ptr = template;
  for (;;) {
    esc = strchrnul(ptr, '%');
    bnmemcpy(&d, &n, ptr, esc - ptr);
    if (!n) break;
    if (esc[0] == '\0') break;
    ptr = esc + 1;

    bool neg = false;
    bool pad = false;
    unsigned int w = 0;
    if (ptr[0] == '%') {
      bnchr(&d, &n, '%');
      continue;
    } else if (ptr[0] == '-') {
      neg = true;
      ++ptr;
    } else if (ptr[0] == '0') {
      pad = true;
      ++ptr;
    }

    if (ptr[0] >= '1' && ptr[0] <= '9') {
      while (w < 100 && ptr[0] >= '0' && ptr[0] <= '9') {
        w = w * 10 + (ptr[0] - '0');
        ++ptr;
      }
    }

    size_t start = 0, end = hashlen;
    switch (ptr[0]) {
      case 'h':
        pad = (w & 1) ? true : false;
        w /= 2;
        if (pad) w += 1;
        if (w) {
          if (w > hashlen) return -1;
          neg ? (start = hashlen - w) : (end = w);
        }
        if (pad && neg) bnprintf(&d, &n, "%x", hash[start++] & 0xf);
        for (size_t i = start; i < end; ++i) bnprintf(&d, &n, "%02x", hash[i]);
        if (pad && !neg) { --d; ++n; }
        break;

      case 'H':
        pad = (w & 1) ? true : false;
        w /= 2;
        if (pad) w += 1;
        if (w) {
          if (w > hashlen) return -1;
          neg ? (start = hashlen - w) : (end = w);
        }
        if (pad && neg) bnprintf(&d, &n, "%X", hash[start++] & 0xf);
        for (size_t i = start; i < end; ++i) bnprintf(&d, &n, "%02X", hash[i]);
        if (pad && !neg) { --d; ++n; }
        break;

      default:
        bnchr(&d, &n, '%');
        bnchr(&d, &n, ptr[0]);
    }
    ++ptr;

    if (!n) break;
  }

  if (n) {
    d[0] = '\0';
    return 0;
  }

  return -1;
}

static void list_digests() {
  struct digest_list *md = get_digest_list();
  if (md == NULL) {
    fprintf(stderr, "Run `openssl list -digest-algorithms` for supported values.\n");
  } else {
    char errbuf[1024];
    size_t n = sizeof(errbuf);
    char *d = errbuf;
    bnstrcpy(&d, &n, "Supported values: ");
    while (md != NULL) {
      bnstrcpy(&d, &n, md->name);
      if (md->next != NULL) bnmemcpy(&d, &n, ", ", 2);
      md = md->next;
    }
    fprintf(stderr, "%s\n", errbuf);
  }
}

int main(int argc, char *argv[]) {
  uint8_t buf[1<<17], *hash;
  int i_fd = 0, o_fd = 1;
  int use_tmp = 0;

  if (argc == 2 && strcmp(argv[1], "list") == 0) {
    list_digests();
    return 0;
  } else if (argc < 3 || argc > 4) {
    fprintf(stderr, "Usage: %s DIGEST [SOURCE] TEMPLATE\n", argv[0]);
    return -1;
  }

  char tmpfile[PATH_MAX+1], destination[PATH_MAX+1];
  const char *digest_name = argv[1];
  char *template = NULL, *source = NULL;

  if (argc == 3) {
    template = argv[2];
  } else if (argc == 4) {
    o_fd = -1;
    source = argv[2];
    template = argv[3];
  }

  const EVP_MD *md = EVP_get_digestbyname(digest_name);
  if (md == NULL) {
    fprintf(stderr, "Unknown hash '%s'!\n", digest_name);
    return -1;
  }

  unsigned int hashlen = EVP_MD_size(md);
  if ((hash = malloc(hashlen)) == NULL) {
    perror("malloc");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    perror("EVP_MD_CTX_new");
    return -1;
  }

  // I don't think this can fail?
  EVP_DigestInit(ctx, md);

  // fill template with dummy value to ensure result will fit ahead of time
  if (fill_template(destination, sizeof(destination), template, hash, hashlen) < 0) {
    fprintf(stderr, "template overflow\n");
    return -1;
  }

  if (source != NULL) {
    if ((i_fd = open(source, O_RDONLY)) < 0) {
      perror("open");
      return -1;
    }

    struct stat st[] = {0};
    if (fstat(i_fd, st) < 0) {
      perror("stat");
      return -1;
    } else if (!S_ISREG(st->st_mode)) {
      use_tmp = 1;
    }
  } else {
    use_tmp = 1;
  }

  if (use_tmp) {
    char *dir, *parent;

    if ((dir = strdup(destination)) == NULL) {
      perror("strdup");
      return -1;
    }

    if ((parent = dirname(dir)) == NULL) {
      perror("dirname");
      return -1;
    }

    // TODO: fallback for when O_TMPFILE/linkat aren't available
    if ((o_fd = open(parent, O_TMPFILE|O_WRONLY, 0600)) < 0) {
      perror("open");
      free(dir);
      return -1;
    }

    free(dir);
  }

  size_t size = 0;
  ssize_t n, r;
  for (;;) {
    uint8_t *ptr = buf;

    // read
    r = n = read(i_fd, ptr, sizeof(buf));
    if (n == 0) break;
    if (n < 0) {
      perror("read");
      return errno;
    }
    size += n;

    // update hash
    EVP_DigestUpdate(ctx, ptr, n);

    if (o_fd < 0) continue;

    // write
    for (;;) {
      n = write(o_fd, ptr, r);
      if (n <= 0) {
        perror("write");
        return errno == 0 ? -1 : errno;
      }
      if ((r = r - n) == 0) break;
      ptr += n;
    }
  }

  EVP_DigestFinal(ctx, hash, NULL);

  {
    char hash_hex[EVP_MAX_MD_SIZE*2+1];
    char *d = hash_hex;
    size_t n = sizeof(hash_hex);
    for (unsigned int i = 0; i < hashlen; ++i) {
      bnprintf(&d, &n, "%02x", hash[i]);
    }
    printf("%s\n", hash_hex);
  }

  // *actually* fill in the template with real data
  if (fill_template(destination, sizeof(destination), template, hash, hashlen) < 0) {
    fprintf(stderr, "template overflow\n");
    return -1;
  }

  if (use_tmp) {
    // This is... asinine. https://stackoverflow.com/a/67568568/370695
    mode_t mask = umask(0777);
    umask(mask);
    fchmod(o_fd, 0666 ^ mask);
    // XXX: Can't use AT_EMPTY_PATH unless we're root.
    snprintf(tmpfile, PATH_MAX, "/proc/self/fd/%d", o_fd);
    if (linkat(AT_FDCWD, tmpfile, AT_FDCWD, destination, AT_SYMLINK_FOLLOW) != 0) {
      perror("linkat");
      return -1;
    }
  } else if (rename(source, destination) != 0) {
    fprintf(stderr, "src: %s\n", source);
    fprintf(stderr, "dst: %s\n", destination);
    perror("rename");
    return -1;
  }

  return 0;
}
