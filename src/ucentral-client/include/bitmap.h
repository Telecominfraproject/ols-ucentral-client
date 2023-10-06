#ifndef BITMAP_DECLARE

#include <stdint.h>

#define BITS_PER_BYTE (8)
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_UINT32(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(uint32_t))
#define BITMAP_SIZE(bits) (BITS_TO_UINT32(bits) * sizeof(uint32_t))
#define BITMAP_BITSIZE(A) (sizeof((A)) * BITS_PER_BYTE)
#define BITMAP_DECLARE(name, bits) uint32_t name[BITS_TO_UINT32(bits)]
#define BITMAP_SET_BIT(A, k) (A[(k) / 32] |= (1 << ((k) % 32)))
#define BITMAP_CLEAR_BIT(A, k) (A[(k) / 32] &= ~(1 << ((k) % 32)))
#define BITMAP_TEST_BIT(A, k) (A[(k) / 32] & (1 << ((k) % 32)))

#define BITMAP_CLEAR(A, s) memset(A, 0, BITS_TO_UINT32(s) * sizeof(uint32_t))
#define BITMAP_FILL(A, s, value) \
	memset(A, value ? 0XFF : 0x0, BITS_TO_UINT32(s) * sizeof(uint32_t))

#define BITMAP_FIND_FIRST_BIT_SET(A, len)               \
	({                                              \
		size_t it = 0;                          \
		for ((it) = 0; (it) < (len); (++it)) {  \
			if (BITMAP_TEST_BIT((A), (it))) \
				break;                  \
		}                                       \
		(it);                                   \
	})

#define BITMAP_FIND_NEXT_BIT_SET(A, len, bit)                            \
	({                                                               \
		size_t it = 0;                                           \
		for ((it) = 0; (it) < (len); (++it)) {                   \
			if (BITMAP_TEST_BIT((A), (it)) && (it) >= (bit)) \
				break;                                   \
		}                                                        \
		(it);                                                    \
	})

#define BITMAP_FOR_EACH_BIT_SET(bit, A, len)                               \
	for ((bit) = BITMAP_FIND_FIRST_BIT_SET((A), (len)); (bit) < (len); \
	     (bit) = BITMAP_FIND_NEXT_BIT_SET((A), (len), (bit) + 1))

#endif
