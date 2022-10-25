// SPDX-License-Identifier: CC0-1.1 OR 0BSD
// Copyright (C) 2022 Ryan Castellucci
#pragma once

#include <stdlib.h>
#include <stdint.h>

ssize_t hexlify(char *dst, size_t dst_sz, const void *src, size_t src_sz);
ssize_t hexline(char *dst, size_t dst_sz, const void *src, size_t src_sz);
