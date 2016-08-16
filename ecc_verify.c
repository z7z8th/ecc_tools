#include <stdio.h>

#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"

/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
  Verify a ECC signature
  @param r        ECC "r" parameter
  @param s        ECC "s" parameter
  @param hash     The hash that was signed
  @param hashlen  The length of the hash that was signed
  @param stat     [out] The result of the signature verification, 1==valid, 0==invalid
  @param key      The corresponding public DH key
  @return CRYPT_OK if successful (even if the signature is invalid)
*/
int ecc_verify_hash_raw_l(      void   *r, void   *s,
                        const unsigned char *hash, unsigned long hashlen,
                        int *stat, ecc_key *key)
{
   ecc_point    *mG, *mQ;
   void          *v, *w, *u1, *u2, *e, *p, *m;
   void          *mp = NULL;
   int           err;

   LTC_ARGCHK(r    != NULL);
   LTC_ARGCHK(s    != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;
   mp    = NULL;

   /* is the IDX valid ?  */
   if (ltc_ecc_is_valid_idx(key->idx) != 1) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* allocate ints */
   if ((err = mp_init_multi(&v, &w, &u1, &u2, &p, &e, &m, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* allocate points */
   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   if (mQ  == NULL || mG == NULL) {
      err = CRYPT_MEM;
      goto error;
   }

   /* get the order */
   if ((err = mp_read_radix(p, (char *)key->dp->order, 16)) != CRYPT_OK)                                { goto error; }

   /* get the modulus */
   if ((err = mp_read_radix(m, (char *)key->dp->prime, 16)) != CRYPT_OK)                                { goto error; }

   /* check for zero */
   if (mp_iszero(r) || mp_iszero(s) || mp_cmp(r, p) != LTC_MP_LT || mp_cmp(s, p) != LTC_MP_LT) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* read hash */
   if ((err = mp_read_unsigned_bin(e, (unsigned char *)hash, (int)hashlen)) != CRYPT_OK)                { goto error; }

   /*  w  = s^-1 mod n */
   if ((err = mp_invmod(s, p, w)) != CRYPT_OK)                                                          { goto error; }

   /* u1 = ew */
   if ((err = mp_mulmod(e, w, p, u1)) != CRYPT_OK)                                                      { goto error; }

   /* u2 = rw */
   if ((err = mp_mulmod(r, w, p, u2)) != CRYPT_OK)                                                      { goto error; }

   /* find mG and mQ */
   if ((err = mp_read_radix(mG->x, (char *)key->dp->Gx, 16)) != CRYPT_OK)                               { goto error; }
   if ((err = mp_read_radix(mG->y, (char *)key->dp->Gy, 16)) != CRYPT_OK)                               { goto error; }
   if ((err = mp_set(mG->z, 1)) != CRYPT_OK)                                                            { goto error; }

   if ((err = mp_copy(key->pubkey.x, mQ->x)) != CRYPT_OK)                                               { goto error; }
   if ((err = mp_copy(key->pubkey.y, mQ->y)) != CRYPT_OK)                                               { goto error; }
   if ((err = mp_copy(key->pubkey.z, mQ->z)) != CRYPT_OK)                                               { goto error; }

   /* compute u1*mG + u2*mQ = mG */
   if (ltc_mp.ecc_mul2add == NULL) {
      if ((err = ltc_mp.ecc_ptmul(u1, mG, mG, m, 0)) != CRYPT_OK)                                       { goto error; }
      if ((err = ltc_mp.ecc_ptmul(u2, mQ, mQ, m, 0)) != CRYPT_OK)                                       { goto error; }
  
      /* find the montgomery mp */
      if ((err = mp_montgomery_setup(m, &mp)) != CRYPT_OK)                                              { goto error; }

      /* add them */
      if ((err = ltc_mp.ecc_ptadd(mQ, mG, mG, m, mp)) != CRYPT_OK)                                      { goto error; }
   
      /* reduce */
      if ((err = ltc_mp.ecc_map(mG, m, mp)) != CRYPT_OK)                                                { goto error; }
   } else {
      /* use Shamir's trick to compute u1*mG + u2*mQ using half of the doubles */
      if ((err = ltc_mp.ecc_mul2add(mG, u1, mQ, u2, mG, m)) != CRYPT_OK)                                { goto error; }
   }

   /* v = X_x1 mod n */
   if ((err = mp_mod(mG->x, p, v)) != CRYPT_OK)                                                         { goto error; }

   /* does v == r */
   dump_mpz("v", v);
   dump_mpz("r", r);
   if (mp_cmp(v, r) == LTC_MP_EQ) {
      *stat = 1;
   }

   /* clear up and return */
   err = CRYPT_OK;
error:
   ltc_ecc_del_point(mG);
   ltc_ecc_del_point(mQ);
   mp_clear_multi(v, w, u1, u2, p, e, m, NULL);
   if (mp != NULL) { 
      mp_montgomery_free(mp);
   }
   return err;
}

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
   err = ecc_verify_hash_raw_l(r, s, hash, hashlen, stat, key);

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
	if(ecc_init_key(keysize, &pubkey)) {
		printf("ecc_init_key failed!\n");
		return -1;
	}
	if(ecc_import_pubkey(keysize, argv[2], &pubkey)) {
		printf("ecc_import_pubkey failed!\n");
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
