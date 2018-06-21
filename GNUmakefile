SOURCES = dunnel.c dtls.c sock.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = fns.h dat.h

CFLAGS ?= -O0 -g
CFLAGS += -std=c99 -Wpedantic -Wall -Wextra \
	  -D_POSIX_C_SOURCE=200112L -DSHA2_USE_INTTYPES_H -I ./tinydtls

LDFLAGS += -ltinydtls -L ./tinydtls

ifeq "$(findstring clang,$(shell $(CC) --version))" "clang"
	CFLAGS += -Weverything
endif

dunnel: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)
$(OBJECTS): $(HEADERS) tinydtls/libtinydtls.a

tinydtls/Makefile:
	cd tinydtls && autoconf
	cd tinydtls && autoheader
	cd tinydtls && ./configure --without-ecc

tinydtls/libtinydtls.a: tinydtls/Makefile
	$(MAKE) CFLAGS="$(CFLAGS) -Wno-error" \
		-C "$(shell dirname $<)" "$(shell basename $@)"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
