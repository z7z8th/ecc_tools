#include <stdio.h>
#include <stdlib.h>
#include "ecc_config.h"
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

int ecc_import_file(const char *file, void *buf, int size) {
	FILE *pf = NULL;
	if(!(pf = fopen(file, "r"))) {
		perror("fopen");
		return -1;
	}

	if(fread(buf, size, 1, pf) != 1) {
		perror("fread");
		return -1;
	}
	fclose(pf);

	return 0;
}

int ecc_export_file(const char *file, void *buf, int size) {
	FILE *pf = NULL;
	if(!(pf = fopen(file, "w+"))) {
		perror("fopen");
		return -1;
	}

	if(fwrite(buf, size, 1, pf) != 1) {
		perror("fwrite");
		return -1;
	}
	fclose(pf);

	return 0;
}

int ecc_init_key(int keysize, ecc_key *key) {
	int x, err;
	if(keysize != ECC_KEY_SIZE) {
		printf("Error: only key size %d is supported currently!\n", ECC_KEY_SIZE);
		return -1;
	}
	/* find key size */
	for (x = 0; (keysize > ltc_ecc_sets[x].size) && (ltc_ecc_sets[x].size != 0); x++)
		;
	keysize = ltc_ecc_sets[x].size;

	if (keysize > ECC_MAXSIZE || ltc_ecc_sets[x].size == 0) {
		return CRYPT_INVALID_KEYSIZE;
	}
	key->type = PK_PRIVATE;
	key->idx = x;
	key->dp = &ltc_ecc_sets[x];

	if ((err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL)) != CRYPT_OK) {
		printf("mp init public and private key failed!\n");
		return err;
	}
	return 0;
}

int ecc_import_pubkey(int keysize, const char *pub_file, ecc_key *key) {
	//int keysize = ECC_KEY_SIZE;
	int err;
	u8 *pub;	//[2][ECC_KEY_SIZE];
	
	pub = calloc(2, keysize);
	if(!pub) {
		printf("failed to alloc mem for public key!\n");
		return -1;
	}
	if(ecc_import_file(pub_file, pub, ECC_KEY_SIZE*2)) {
		printf("import public key from file failed!\n");
		return -1;
	}

	if((err = mp_read_unsigned_bin(key->pubkey.x, pub, keysize)) != CRYPT_OK) {
		printf("import public key .x failed!\n");
		return err;
	}
	if((err = mp_read_unsigned_bin(key->pubkey.y, pub+keysize, keysize)) != CRYPT_OK) {
		printf("import public key .y failed!\n");
		return err;
	}
	if ((err = mp_set(key->pubkey.z, 1)) != CRYPT_OK) {
		printf("set public key .z failed!\n");
		return err;
	}

	return 0;
}


int ecc_import_privkey(int keysize, const char *priv_file, ecc_key *key) {
	//int keysize = ECC_KEY_SIZE;
	int err;
	u8 *priv;	//[ECC_KEY_SIZE];
	
	priv = calloc(1, keysize);
	if(!priv) {
		printf("failed to alloc mem for private key!\n");
		return -1;
	}
	if(ecc_import_file(priv_file, priv, keysize)) {
		printf("import private key from file failed!\n");
		return -1;
	}
	
	if((err = mp_read_unsigned_bin(key->k, priv, keysize)) != CRYPT_OK) {
		printf("import private key failed!\n");
		return err;
	}

	return 0;
}

int ecc_init_import_keys(int keysize,  const char *pub_file, const char *priv_file, ecc_key *key) {
	if(ecc_init_key(keysize, key))
		return -1;
	if(ecc_import_pubkey(keysize, pub_file, key))
		return -1;
	if(ecc_import_privkey(keysize, priv_file, key))
		return -1;
	return 0;
}


