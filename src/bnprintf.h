// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2022 Ryan Castellucci
#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

ssize_t bnchr(char **d, size_t *n, char c);
ssize_t bnmemcpy(char **d, size_t *n, const char *s, size_t len);
ssize_t bnstrcpy(char **d, size_t *n, const char *s);
ssize_t bnprintf(char **d, size_t *n, const char *format, ...);
