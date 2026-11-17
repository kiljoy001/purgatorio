#ifndef _BEAR_STDINT_H
#define _BEAR_STDINT_H
#ifdef __GNUC__
#include_next <stdint.h>
#else
#include <bear9.h>
typedef u8int uint8_t;
typedef u16int uint16_t;
typedef u32int uint32_t;
typedef u64int uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef vlong int64_t;
typedef ulong uintptr_t;
#endif
#endif
