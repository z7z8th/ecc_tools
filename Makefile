.PHONY: all clean

CFLAGS := -g3 -O2 -Wall -I../libtomcrypt-develop-20160729/src/headers
DEFINES := -DLTC_SOURCE -DUSE_GMP -DGMP_DESC
LDFLAGS := -L../libtomcrypt-develop-20160729
LIBS := -ltomcrypt -lgmp
CC := gcc
LD := gcc

OBJS := ecc_tools.o ecc_sign.o ecc_verify.o ecc_keygen.o ecc_utils.o
TARGET := ecc_tools

%.o: %.c
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o$@

all: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o$(TARGET)

clean:
	-rm *.o
	-rm *.exe
