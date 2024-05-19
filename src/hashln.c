// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2024 Ryan Castellucci
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "digestlist.h"
#include "bnprintf.h"
#include "hexlify.h"

int main(int argc, char **argv) {
  char *line = NULL;
  size_t line_sz = 0;
  ssize_t r, line_read;
  unsigned char hash[64];
  char hexed[130];

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s HASH [STRING]\n", argv[0]);
    return -1;
  }

  const EVP_MD *md = EVP_get_digestbyname(argv[1]);
  if (md == NULL) {
    fprintf(stderr, "Unknown hash '%s'\n", argv[1]);
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    perror("EVP_MD_CTX_new");
    return -1;
  }

  unsigned int hashlen = EVP_MD_size(md);

  EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);

  if (argc == 3) {
    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, argv[2], strlen(argv[2]));
    EVP_DigestFinal(ctx, hash, NULL);
    if ((r = hexline(hexed, sizeof(hexed), hash, hashlen)) < -1) return -1;
    fwrite(hexed, 1, r, stdout);
    return 0;
  }

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, line, line_read-1);
    EVP_DigestFinal(ctx, hash, NULL);
    r = hexline(hexed, sizeof(hexed), hash, hashlen);
    hexed[r-1] = '\t';
    fwrite(hexed, 1, r, stdout);
    fwrite(line, 1, line_read, stdout);
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
