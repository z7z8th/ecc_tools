#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"

//#define DEBUG

int ecc_export_key(int fd_pub, int fd_priv, ecc_key *key) {
	u8 pub[2][ECC_KEY_SIZE];
	u8 priv[ECC_KEY_SIZE];
	
	if(mp_to_unsigned_bin(key->pubkey.x, pub[0]) != CRYPT_OK) {
		printf("%s: pub key x to buf failed!\n", __func__);
		return -1;
	}
	if(mp_to_unsigned_bin(key->pubkey.y, pub[1]) != CRYPT_OK) {
		printf("%s: pub key x to buf failed!\n", __func__);
		return -1;
	}
	if(mp_to_unsigned_bin(key->k, priv) != CRYPT_OK) {
		printf("%s: pub key x to buf failed!\n", __func__);
		return -1;
	}
	
#if DUMP_KEYS
	print_hex("public key:\n", 4, pub, mp_unsigned_bin_size(key->pubkey.x)*2);
	print_hex("private key:\n", 4, priv, mp_unsigned_bin_size(key->k));
#endif
	if(write(fd_pub, pub, ECC_KEY_SIZE*2) != ECC_KEY_SIZE*2) {
		perror("write pub key");
		return -1;
	}
	if(write(fd_priv, priv, ECC_KEY_SIZE) != ECC_KEY_SIZE) {
		return -1;
	}
	memset(pub, 0, ECC_KEY_SIZE*2);
	memset(priv, 0, ECC_KEY_SIZE);
	return 0;
}


#define ECC_VERIFY_PUBKEY_PASS_CNT 3

int ecc_verify_pubkey_ex(ecc_key *key, int *stat) {
	ecc_point *base = NULL;
	ecc_point *mQ = NULL;   // mQ = (order+1)*pubkey
	void *l, *r;
	void *prime, *order, *B;
	int err = 0;
	*stat = 0;

	/* Verify that Q is not the point at infinity O*/
	if(mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y)) {
		printf("key->pubkey == infini. fail!\n");
		err = CRYPT_ERROR;
		return err;
	} else {
		*stat += 1;
		printf("key->pubkey != infini. pass!\n");
		err = CRYPT_OK;
	}

	/* 2. Verify that x Q  and y Q  are elements in the field F q , where x Q  and y Q  are the x and y coordinates of Q,
		respectively. (That is, verify that x Q  and y Q  are integers in the interval [0, p-1] in the case that q = p is an
		odd prime, or that x Q  and y Q  are bit strings of length m bits in the case that q = 2m.)
		3. If q = p is an odd prime, verify that yQ2  =  xQ3 + ax Q  + b (mod p). If q = 2m, 
		verify that yQ2 + xQyQ  = xQ3 +	axQ2 + b in F2m. 
	*/
	if((err = mp_init_multi(&l, &r, &prime, &order, &B, NULL)) != CRYPT_OK) { 
		return CRYPT_MEM;
	}
	
	base = ltc_ecc_new_point();
	if (base == NULL) {
		err = CRYPT_MEM;
		goto error;
	}

	mQ = ltc_ecc_new_point();
	if (mQ == NULL) {
		err = CRYPT_MEM;
		goto error;
	}

	if((err = mp_read_radix(order, (char *)key->dp->order, 16)) != CRYPT_OK)	{ goto error; }
	if((err = mp_read_radix(prime, (char *)key->dp->prime, 16)) != CRYPT_OK)	{ goto error; }
	if((err = mp_read_radix(B, (char *)key->dp->B, 16)) != CRYPT_OK)	{ goto error; }

	if((err = mp_mulmod(key->pubkey.y, key->pubkey.y, prime, l)) != CRYPT_OK)	{ goto error; }

#if 1
	if((err = mp_mulmod(key->pubkey.x, key->pubkey.x, prime, r)) != CRYPT_OK)	{ goto error; }
	if((err = mp_sub_d(r, 3, r)) != CRYPT_OK)	{ goto error; }
	if((err = mp_mulmod(r, key->pubkey.x, prime, r)) != CRYPT_OK)	{ goto error; }
	if((err = mp_addmod(r, B, prime, r)) != CRYPT_OK)	{ goto error; }
	//if((err = mp_mod(r, prime, r)) != CRYPT_OK)	{ goto error; }
#else
	if((err = mp_mulmod(key->pubkey.x, key->pubkey.x, prime, r)) != CRYPT_OK)	{ goto error; }
	if((err = mp_mulmod(r, key->pubkey.x, prime, r)) != CRYPT_OK)	{ goto error; }
	void *a_3x;
	mp_init(&a_3x);
	mp_set_int(a_3x, 3);
	if((err = mp_mulmod(a_3x, key->pubkey.x, prime, a_3x)) != CRYPT_OK)	{ goto error; }
	if((err = mp_sub(r, a_3x, r)) != CRYPT_OK)	{ goto error; }
	//mp_set_int(a_3x, 1);
	if((err = mp_add(r, B, r)) != CRYPT_OK)	{ goto error; }
	if((err = mp_mod(r, prime, r)) != CRYPT_OK)	{ goto error; }
#endif

#ifdef DEBUG
	dump_mpz("l", l);
	dump_mpz("r", r);
#endif
	if(mp_cmp(l, r) == LTC_MP_EQ) {
		printf("ecc public key point verify l == r passed!\n");
		*stat += 1;
		err = CRYPT_OK;
	} else {
		printf("ecc public key point verify l != r failed!\n");
		err = CRYPT_ERROR;
	}
	
	if ((err = mp_read_radix(base->x, (char *)key->dp->Gx, 16)) != CRYPT_OK)		     { goto error; }
	if ((err = mp_read_radix(base->y, (char *)key->dp->Gy, 16)) != CRYPT_OK)		     { goto error; }
	if ((err = mp_set(base->z, 1)) != CRYPT_OK)						     { goto error; }

	/* Verify that nQ = O. (See Annex D.3.2.) */
	//if((err = mp_add_d(order, 1, order)) != CRYPT_OK)					{ goto error; }
	if ((err = ltc_mp.ecc_ptmul(order, &key->pubkey, mQ, prime, 1)) != CRYPT_OK)      { goto error; }

#ifdef DEBUG
	dump_mpz("pubkey.x", key->pubkey.x);
	dump_mpz("pubkey.y", key->pubkey.y);
	dump_mpz("pubkey.z", key->pubkey.z);

	dump_mpz("infini mQ->x", mQ->x);
	dump_mpz("infini mQ->y", mQ->y);
	dump_mpz("infini mQ->z", mQ->z);
#endif
#if 0
	void *t;
	mp_init(&t);
	mp_set_int(t, 0);
	dump_mpz("t", t);
	mp_clear(t);
#endif

	if(mp_iszero(mQ->x) && mp_iszero(mQ->y)) {
		*stat += 1;
		printf("(order)*key->pubkey == infini. pass!\n");
		err = CRYPT_OK;
	} else {
		printf("(order)*key->pubkey != infini. fail!\n");
		err = CRYPT_ERROR;
	}
error:
	ltc_ecc_del_point(mQ);
	ltc_ecc_del_point(base);
	mp_clear_multi(l, r, prime, order, B, NULL);
	
	if(*stat == ECC_VERIFY_PUBKEY_PASS_CNT)
		*stat = 1;
	else
		*stat = 0;

	return err;
}

int ecc_keygen(int argc, char *argv[]) {
	int ret;
	int fd_pub;
	int fd_priv;
	ecc_key key;
	if(argc != 4) {
		printf("usage:\n %s pubkey_file privkey_file\n", argv[0]);
		return -1;
	}
	ret = ecc_make_key (&yarrow_prng, find_prng ("yarrow"), ECC_KEY_SIZE, &key);
	if(ret) {
		printf("ecc_make_key failed! ret %d (%s)\n", ret, error_to_string(ret));
		return ret;
	}

	if((fd_pub = open(argv[2], O_WRONLY|O_CREAT)) < 0) {
		perror("open pubkey_file");
		return -1;
	}

	if((fd_priv = open(argv[3], O_WRONLY|O_CREAT)) < 0) {
		perror("open privkey_file");
		return -1;
	}
	ret = ecc_export_key(fd_pub, fd_priv, &key);
	close(fd_priv);
	close(fd_pub);

	return ret;
}

int ecc_verify_pubkey(int argc, char *argv[]) {
	ecc_key pubkey;
	const int keysize = ECC_HASH_SIZE;
	int err = 0;
	int stat = 0;
	
	if(argc != 3) {
		printf("usage:\n %s pubkey_file\n", argv[0]);
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

	if((err = ecc_verify_pubkey_ex(&pubkey, &stat)) != CRYPT_OK) {
		printf("ecc_verify_pubkey_ex failed! err %d\n", err);
		return err;
	}
	printf("verify public key %s\n", stat ? "succeed! ;-)" : "failed! ;-( T_T");
	return (stat == 0); // return zero on success
}

