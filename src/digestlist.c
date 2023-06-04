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

#include "digestlist.h"

void free_digest_list(struct digest_list *entry) {
  struct digest_list *next;
  do {
    next = entry->next;
    if (entry->name != NULL) free(entry->name);
    if (entry->ctx != NULL) EVP_MD_CTX_free(entry->ctx);
    free(entry);
  } while ((entry = next) != NULL);
}

struct digest_list * new_digest_list() {
  struct digest_list *entry;

  if ((entry = malloc(sizeof(struct digest_list))) != NULL) {
    entry->name = NULL;
    entry->next = NULL;
  }

  return entry;
}

// somewhat based on code in openssl's apps/dgst.c
static void _get_digest(const OBJ_NAME *name, void *arg) {
  struct digest_list **ptr = (struct digest_list **)arg;
  struct digest_list *entry;

  // detect failure on previous call
  if (*ptr == NULL) return;

  const EVP_MD *md;
  unsigned int len = 0;
  char tmp_name[64];
  while (len < sizeof(tmp_name)) {
    tmp_name[len] = tolower(name->name[len]);
    if (tmp_name[len] == '\0') break;
    ++len;
  }
  if (tmp_name[len++] != '\0') {
    fprintf(stderr, "Digest name `%s` too long!\n", name->name);
    goto _get_digest_error;
  }

  // Filter out signed digests/signature algorithms and ssl-specific stuff
  if (strstr(tmp_name, "rsa") != NULL) return;
  if (strstr(tmp_name, "ssl3") != NULL) return;
  if (strstr(tmp_name, "md5-sha1") != NULL) return;

  // Filter out message digests that we cannot use
  if ((md = EVP_get_digestbyname(tmp_name)) == NULL) return;

  if ((*ptr)->name == NULL) {
    // current entry is empty, therefore start of list
    entry = *ptr;
  } else {
    // current entry contains data
    if ((entry = new_digest_list()) == NULL) {
      fprintf(stderr, "new_digest_list() failed: %s\n", strerror(errno));
      goto _get_digest_error;
    }
  }

  if ((entry->name = malloc(len)) == NULL) {
    fprintf(stderr, "malloc of entry->name failed: %s\n", strerror(errno));
    free(entry);
    goto _get_digest_error;
  }

  memcpy(entry->name, tmp_name, len);
  entry->alias = name->alias;
  entry->md = md;
  entry->ctx = NULL;
  entry->type = EVP_MD_type(md);
  entry->hashlen = EVP_MD_size(md);
  entry->blocklen = EVP_MD_block_size(md);
  entry->next = NULL;

  if (*ptr != entry) {
    // update next and list pointers
    (*ptr)->next = entry;
    *ptr = entry;
  }
  return;

_get_digest_error:
  *ptr = NULL;
}

struct digest_list * get_digest_list() {
  struct digest_list *entry, *first;
  if ((first = entry = new_digest_list()) == NULL) {
    fprintf(stderr, "new_digest_list() failed: %s\n", strerror(errno));
    return NULL;
  }

  EVP_get_digestbyname(NULL);
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, _get_digest, &entry);

  return first;
}

struct digest_list * tail_digest_list(struct digest_list *entry) {
  while (entry != NULL && entry->next != NULL) entry = entry->next;
  return entry;
}

int append_digest_list(struct digest_list *head, struct digest_list *tail) {
  if ((head = tail_digest_list(head)) == NULL) return -1;
  head->next = tail;
  return 0;
}

struct digest_list * extend_digest_list(struct digest_list *list) {
  struct digest_list *entry;
  if ((entry = new_digest_list()) == NULL) return NULL;
  if (append_digest_list(list, entry) != 0) {
    free_digest_list(entry);
    return NULL;
  }
  return entry;
}
