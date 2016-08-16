#include <stdio.h>

#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"


/**
  Sign a message digest - out[2][keysize]
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_bin(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, ecc_key *key)
{
   void          *r, *s;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (mp_init_multi(&r, &s, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   if ((err = ecc_sign_hash_raw(in, inlen, r, s, prng, wprng, key)) != CRYPT_OK) {
      goto error;
   }
   if((err = mp_to_unsigned_bin(r, out)) != CRYPT_OK) {
   	goto error;
   }
   *outlen = mp_unsigned_bin_size(r);
   if((err = mp_to_unsigned_bin(s, out+ECC_KEY_SIZE)) != CRYPT_OK) {
   	goto error;
   }
   *outlen += mp_unsigned_bin_size(s);

error:
   mp_clear_multi(r, s, NULL);
   return err;   
}

int ecc_sign(int argc, char *argv[]) {
	ecc_key key;
	const int keysize = ECC_HASH_SIZE;
	u8 *hash;	//[ECC_HASH_SIZE];
	u8 *signature;	//[2][ECC_KEY_SIZE];
	unsigned long sig_len = keysize*2;
	int err = 0;
	
	if(argc != 6) {
		printf("usage:\n %s pubkey_file privkey_file hash_file signature_file\n", argv[0]);
		return -1;
	}
	hash = calloc(1, keysize);
	signature = calloc(2, keysize);
	if(!hash || !signature) {
		printf("alloc mem failed for hash %p or signature %p\n", hash, signature);
		return -1;
	}
	if(ecc_init_import_keys(keysize, argv[2], argv[3], &key)) {
		printf("ecc_import_keys failed!\n");
		return -1;
	}

	if(ecc_import_file(argv[4], hash, keysize)) {
		printf("import hash failed!\n");
		return -1;
	}
	if((err = ecc_sign_hash_bin(hash, keysize, (void *)signature, &sig_len, 
					&yarrow_prng, find_prng("yarrow"), &key)) != CRYPT_OK) {
		printf("ecc_sign_hash failed! err %d\n", err);
		return err;
	}
	if(keysize*2 != sig_len) {
		printf("geneated signature length is not ECC_KEY_SIZE*2\n");
		return -1;
	}
	if(ecc_export_file(argv[5], signature, keysize*2)) {
		printf("ecc export signature to file failed!\n");
		return -1;
	}
	return 0;
}
