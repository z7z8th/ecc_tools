#include <stdio.h>
#include <stdlib.h>
#include "ecc_utils.h"

void print_hex(const char* what, const unsigned long group, const void *p1, const unsigned long len)
{
	const unsigned char* p = p1;
	unsigned long g;
	unsigned long x;
	unsigned long idx = 0;
	printf("%s contents: \n", what);
	for (x = 0; x < len; ) {
		if (!(x % 16)) {
			printf("%04lx: ", idx++);
		}
		for(g=group; g>0; g--) {
			if(x+g-1 >= len)
				continue;
			printf("%02x", p[x+g-1]);
		}
		printf(" ");
		x += group;
		if (group ==1 && !(x % 4) && (x % 16)) {
			printf("  ");
		}
		if (!(x % 16)) {
			printf("\n");
		}
	}
	printf("\n");
}


prng_state yarrow_prng;

void reg_algs(void) {
	int err = 0;
	register_cipher (&aes_desc);
	register_hash (&sha384_desc);
	register_prng(&yarrow_desc);
	ltc_mp = gmp_desc;
	if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
		fprintf(stderr, "rng_make_prng failed: %s\n", error_to_string(err));
		exit(EXIT_FAILURE);
	}

	if (strcmp("CRYPT_OK", error_to_string(err))) {
		exit(EXIT_FAILURE);
	}
}

