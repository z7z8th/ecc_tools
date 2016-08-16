#ifndef __ECC_UTILS_H__
#define __ECC_UTILS_H__
#include <tomcrypt.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

void print_hex(const char* what, const unsigned long group, const void *p1, const unsigned long len);
extern prng_state yarrow_prng;
void reg_algs(void);

#endif

