#ifndef __ECC_UTILS_H__
#define __ECC_UTILS_H__
#include <gmp.h>
#include <tomcrypt.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

extern prng_state yarrow_prng;

void print_hex(const char* what, const unsigned long group, const void *p1, const unsigned long len);
void dump_mpz(const char * what, mpz_t n);
void reg_algs(void);
int ecc_import_file(const char *file, void *buf, int size);
int ecc_export_file(const char *file, void *buf, int size);
int ecc_init_key(int keysize, ecc_key *key);
int ecc_import_pubkey(int keysize, const char *pub_file, ecc_key *key);
int ecc_import_privkey(int keysize, const char *priv_file, ecc_key *key);
int ecc_init_import_keys(int keysize,  const char *pub_file, const char *priv_file, ecc_key *key);

#endif

