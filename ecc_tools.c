#include <stdio.h>
#include <stdlib.h>
#include <tomcrypt.h>
#include "ecc_config.h"
#include "ecc_utils.h"
#include "ecc_tools.h"

struct func_tbl {
	const char * name;
	int (*func)(int, char *[]);
};

struct func_tbl func_tbl[] = {
	{ "keygen", ecc_keygen },
	{ "sign", ecc_sign },
	{ "verify", ecc_verify },
	{ "verify_pubkey", ecc_verify_pubkey},
	{ "", NULL },
};

void dump_commands(void) {
	size_t i;
	printf("availble commands are:\n");
	for(i=0; i<ARRAY_SIZE(func_tbl); i++) {
		printf(func_tbl[i].name);
		printf("  ");
	}
	printf("\n");
}

int main(int argc, char *argv[]) {
	size_t i = 0;
	int err = 0;
	if(argc < 2) {
		printf("need a command!\n");
		dump_commands();
		return -1;
	}

	reg_algs();

	for(i=0; i<ARRAY_SIZE(func_tbl); i++) {
		if(!strcmp(argv[1], func_tbl[i].name)) {
			err = func_tbl[i].func(argc, argv);
			break;
		}
	}
	if(i == ARRAY_SIZE(func_tbl)) {
		printf("unrecoginzed command: %s\n", argv[1]);
		dump_commands();
		return -1;
	}
	return err;
}

