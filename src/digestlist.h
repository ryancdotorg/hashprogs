// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2022 Ryan Castellucci
#pragma once

#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include "digestlist.h"

struct digest_list {
  char *name;
  int alias;
  const EVP_MD *md;
  EVP_MD_CTX *ctx;
  int type;
  size_t hashlen;
  size_t blocklen;
  struct digest_list *next;
};

void free_digest_list(struct digest_list *entry);

struct digest_list * get_digest_list();
