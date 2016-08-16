#include <stdio.h>

#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"

/**
   Verify an ECC signature - sig[2][keysize]
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/

int ecc_verify_hash_bin(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen,
                    int *stat, ecc_key *key)
{
   void          *r, *s;
   int           err;
   int           keysize;
   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* allocate ints */
   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   keysize = key->dp->size;

   /* parse header */
   if((err = mp_read_unsigned_bin(r, (void *)sig, keysize)) != CRYPT_OK) { goto error; }
   if((err = mp_read_unsigned_bin(s, (void *)sig+keysize, keysize)) != CRYPT_OK) { goto error; }

   /* do the op */
   err = ecc_verify_hash_raw(r, s, hash, hashlen, stat, key);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}



//ecc_verify_hash (buf[1], x, buf[0], 16, &stat, &pubKey)

int ecc_verify(int argc, char *argv[]) {
	ecc_key pubkey;
	const int keysize = ECC_HASH_SIZE;
	u8 *hash;	//[ECC_HASH_SIZE];
	u8 *signature;	//[2][ECC_KEY_SIZE];
	unsigned long sig_len = keysize*2;
	int err = 0;
	int stat = 0;
	
	if(argc != 5) {
		printf("usage:\n %s pubkey_file hash_file signature_file\n", argv[0]);
		return -1;
	}
	hash = calloc(1, keysize);
	signature = calloc(2, keysize);
	if(!hash || !signature) {
		printf("alloc mem failed for hash %p or signature %p\n", hash, signature);
		return -1;
	}
	if(ecc_init_key(keysize, &pubkey))
		return -1;
	if(ecc_import_pubkey(keysize, argv[2], &pubkey)) {
		printf("ecc_import_keys failed!\n");
		return -1;
	}

	if(ecc_import_file(argv[3], hash, keysize)) {
		printf("import hash failed!\n");
		return -1;
	}
	if(ecc_import_file(argv[4], signature, sig_len)) {
		printf("import signature failed!\n");
		return -1;
	}
	if((err = ecc_verify_hash_bin(signature, sig_len, hash, keysize, 
					&stat, &pubkey)) != CRYPT_OK) {
		printf("ecc_verify_hash failed! err %d\n", err);
		return err;
	}
	printf("verify hash %s\n", stat ? "succeed! ;-)" : "failed! ;-( T_T");
	return (stat == 0); // return zero on success
}
