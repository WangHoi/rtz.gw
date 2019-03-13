#pragma once

#ifndef SAME_TYPE
#define SAME_TYPE(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

#define WRITE_FENCE asm volatile ("" : : : "memory")
#define ATOMIC_COMPARE_AND_SWAP(pval, old_val, new_val) __sync_bool_compare_and_swap(pval, old_val, new_val)

#ifndef MIN
#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

#ifndef MAX
#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#endif

#ifndef ABS
#define ABS(x) (((x) < 0) ? -(x) : (x))
#endif

#ifndef BITS_PER_LONG
#define BITS_PER_LONG  (sizeof(long) * 8)
#endif
#undef HAVE_ARCH__HASH_32

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

