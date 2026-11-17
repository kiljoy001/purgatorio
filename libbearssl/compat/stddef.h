#ifndef _BEAR_STDDEF_H
#define _BEAR_STDDEF_H
#ifdef __GNUC__
#include_next <stddef.h>
#else
#include <bear9.h>
#ifndef NULL
#define NULL ((void*)0)
#endif
typedef long ptrdiff_t;
#endif
#endif
