CFLAGS ?= -O0 -g
CFLAGS += -std=c99 -Wpedantic -Wall -Wextra \
	  -DSHA2_USE_INTTYPES_H -I ./tinydtls

LDFLAGS += -ltinydtls -L ./tinydtls

ifeq "$(findstring clang,$(shell $(CC) --version))" "clang"
	CFLAGS += -Weverything
endif

dunnel: dunnel.o dtls.o tinydtls/libtinydtls.a
	$(CC) -o $@ $^ $(LDFLAGS)

tinydtls/Makefile:
	cd tinydtls && autoconf
	cd tinydtls && autoheader
	cd tinydtls && ./configure --without-ecc

tinydtls/libtinydtls.a: tinydtls/Makefile
	$(MAKE) CFLAGS="$(CFLAGS) -Wno-error" \
		-C "$(shell dirname $<)" "$(shell basename $@)"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
