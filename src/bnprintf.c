// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2022 Ryan Castellucci
#include "bnprintf.h"

ssize_t bnchr(char **d, size_t *n, char c) {
  if (c == 0 && *n > 0) {
    (*d)[0] = '\0';
    return 0;
  } else if (*n > 1) {
    (*d)[0] = c;
    (*d)[1] = '\0';
    --*n;
    ++*d;
    return 1;
  } else {
    return -1;
  }
}

ssize_t bnmemcpy(char **d, size_t *n, const char *s, size_t len) {
  if (len >= *n) return -1;
  memcpy(*d, s, len);
  *n -= len;
  *d += len;
  return len;
}

ssize_t bnstrcpy(char **d, size_t *n, const char *s) {
  // length excluding null byte
  size_t len = strnlen(s, *n);
  if (len == *n) return -1;
  memcpy(*d, s, len + 1);
  *n -= len;
  *d += len;
  return len;
}

ssize_t bnprintf(char **d, size_t *n, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  // length excluding null byte
  ssize_t len = vsnprintf(*d, *n, format, ap);
  va_end(ap);
  if (len < 0 || (size_t)len >= *n) return -1;
  *n -= len;
  *d += len;
  return len;
}
