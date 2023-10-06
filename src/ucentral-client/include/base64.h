#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

#define BASE64_ENCODE_OUT_SIZE(s) ((size_t)((((s) + 2) / 3) * 4 + 1))
#define BASE64_DECODE_OUT_SIZE(s) ((size_t)(((s) / 4) * 3))

/*
 * out is null-terminated encode string.
 * return values is out length, exclusive terminating `\0'
 */
size_t base64_encode(const unsigned char *in, size_t inlen, char *out);

/*
 * return values is out length
 */
size_t base64_decode(const char *in, size_t inlen, unsigned char *out);

#endif /* BASE64_H */

