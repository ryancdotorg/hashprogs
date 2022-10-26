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
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include <linux/limits.h>

#include "digestlist.h"
#include "bnprintf.h"

#define BUF_SZ 65536

static inline size_t max(size_t a, size_t b) {
  return a > b ? a : b;
}

static int allsum(FILE *f, const char *name, struct digest_list *md, unsigned char *buf, size_t sz) {
  struct digest_list *md_first = md;
  unsigned char hash[EVP_MAX_MD_SIZE];
  char fmt[256];
  char hex[EVP_MAX_MD_SIZE*2+1];
  size_t w = 0;
  size_t n;

  // initialize all digests
  while (md != NULL) {
    w = max(w, strlen(md->name));
    if ((md->ctx = EVP_MD_CTX_new()) == NULL) {
      fprintf(stderr, "EVP_MD_CTX_new() failed!\n");
      return -1;
    }
    EVP_DigestInit(md->ctx, md->md);
    md = md->next;
  }

  // process file data
  do {
    n = fread(buf, 1, sz, f);

    // update all digests with this block of data
    md = md_first;
    while (md != NULL) {
      EVP_DigestUpdate(md->ctx, buf, n);
      md = md->next;
    }
  } while (n == sz);

  if (!feof(f)) {
    fprintf(stderr, "reading %s failed: %s\n", name, strerror(errno));
    return -1;
  }

  md = md_first;
  while (md != NULL) {
    EVP_DigestFinal(md->ctx, hash, NULL);

    // format hash as hex
    char *d = hex;
    size_t space = sizeof(hex);
    for (size_t i = 0; i < md->hashlen; ++i) {
      bnprintf(&d, &space, "%02x", hash[i]);
    }

    // create padded format string
    size_t x = 0;
    d = fmt; space = sizeof(fmt);
    x += bnchr(&d, &space, '(');
    x += bnstrcpy(&d, &space, md->name);
    x += bnchr(&d, &space, ')');
    while (x < w + 4) x += bnchr(&d, &space, ' ');
    bnmemcpy(&d, &space, "%s  %s\n", 8);

    // print file hash
    printf(fmt, name, hex);

    md = md->next;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int ret = 0;
  unsigned char *buf;

  // initialize things...
  if ((buf = malloc(BUF_SZ)) == NULL) {
    fprintf(stderr, "Could not allocate buffer: %s\n", strerror(errno));
    return -1;
  }

  struct digest_list *md;
  if ((md = get_digest_list()) == NULL) {
    fprintf(stderr, "Failed to get digest list!\n");
    return -1;
  }

  { // remove aliases from the digest list
    struct digest_list *prev = NULL, *curr = md, *next;
    while (curr != NULL) {
      next = curr->next;
      if (curr->alias) {
        if (prev == NULL) {
          // update start of list
          md = next;
        } else {
          // unlink current entry from list
          prev->next = next;
        }
        // free discarded entry
        free(curr);
      } else {
        prev = curr;
      }
      // next entry
      curr = next;
    }
  }

  if (argc == 1) {
    // read stdin if no arguments
    ret = allsum(stdin, "-", md, buf, BUF_SZ) || ret;
  } else {
    // read each file listed as an argument
    for (int i = 1; i < argc; ++i) {
      FILE *f;
      const char *filename = argv[i];
      // > [...] the 'b' is ignored on all POSIX conforming systems, including
      // > Linux. (Other systems may treat text files and binary files
      // > differently, and adding the 'b' may be a good idea if you do I/O to
      // > a binary file and expect that your program may be ported to non-UNIX
      // > environments.)
      if ((f = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "Failed to open `%s` for reading: %s\n", filename, strerror(errno));
        ret = -1;
        continue;
      }

      ret = allsum(f, filename, md, buf, BUF_SZ) || ret;
    }
  }

  free_digest_list(md);

  return ret;
}
