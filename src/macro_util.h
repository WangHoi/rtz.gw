#pragma once

#ifndef SAME_TYPE
#define SAME_TYPE(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef UNUSED
#define UNUSED(X) {typeof(X)  __attribute__((__unused__)) _unused = (X); }
#endif

#define WRITE_FENCE asm volatile ("" : : : "memory")
#define WRITE_MFENCE asm volatile ("mfence" : : : "memory")
#define FULL_FENCE __sync_synchronize()
#define ATOMIC_COMPARE_AND_SWAP(pval, old_val, new_val) __sync_bool_compare_and_swap(pval, old_val, new_val)
#define ATOMIC_LOAD(pval) __atomic_load_n(pval, __ATOMIC_ACQUIRE)
#define ATOMIC_LOAD_RELAXED(pval) __atomic_load_n(pval, __ATOMIC_RELAXED)
#define ATOMIC_STORE(pval, new_val) __atomic_store_n(pval, new_val, __ATOMIC_RELEASE)
#define ATOMIC_STORE_RELAXED(pval, new_val) __atomic_store_n(pval, new_val, __ATOMIC_RELAXED)
#define ATOMIC_ADD(pval, new_val) __atomic_add_fetch(pval, new_val, __ATOMIC_RELEASE)
#define ATOMIC_ADD_RELAXED(pval, new_val) __atomic_add_fetch(pval, new_val, __ATOMIC_RELAXED)

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
