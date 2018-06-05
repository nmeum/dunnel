SOURCES = dunnel.c dtls.c
OBJECTS = $(SOURCES:.c=.o)

CFLAGS ?= -O0 -g
CFLAGS += -std=c99 -Wpedantic -Wall -Wextra \
	  -DSHA2_USE_INTTYPES_H -I ./tinydtls

LDFLAGS += -ltinydtls -L ./tinydtls

ifeq "$(findstring clang,$(shell $(CC) --version))" "clang"
	CFLAGS += -Weverything
endif

$(OBJECTS): tinydtls/libtinydtls.a
dunnel: dunnel.o dtls.o
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
