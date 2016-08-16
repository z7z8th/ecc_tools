#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"


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
