#ifndef __ECC_CONFIG_H__
#define __ECC_CONFIG_H__
#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;


#define ECC_KEY_BITS	(384)
#define ECC_KEY_SIZE	(ECC_KEY_BITS/8)
#define ECC_CURVE	"y^2=x^3+ax+b"
#define ECC_CURVE_A	(-3)
#define ECC_CURVE_B	(1)

#define DUMP_KEYS	1
#endif
