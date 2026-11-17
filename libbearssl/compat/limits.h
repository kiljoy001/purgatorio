#ifndef _BEAR_LIMITS_H
#define _BEAR_LIMITS_H
#ifdef __GNUC__
#include_next <limits.h>
#else
#include <bear9.h>
#define CHAR_BIT 8
#define INT_MAX 2147483647
#define UINT_MAX 4294967295U
#define LONG_MAX 2147483647L
#define ULONG_MAX 4294967295UL
#endif
#endif
