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
	{"", NULL},
};



int main(int argc, char *argv[]) {
	int i = 0;
	if(argc < 2) {
		printf("need a command! availble commands are:\n");
		for(i=0; i<ARRAY_SIZE(func_tbl); i++) {
			printf(func_tbl[i].name);
			printf("  ");
		}
		printf("\n");
		return -1;
	}

	reg_algs();

	for(i=0; i<ARRAY_SIZE(func_tbl); i++) {
		if(!strcmp(argv[1], func_tbl[i].name)) {
			func_tbl[i].func(argc, argv);
		}
	}
}

