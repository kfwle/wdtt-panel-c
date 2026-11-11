CC      ?= cc
CFLAGS  ?= -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS ?=
LIBS     = -lsqlite3 -lssl -lcrypto -lpthread

SRC := $(wildcard src/*.c)
OBJ := $(sort $(SRC:.c=.o) src/ui_html.o)

wdttpanel: $(OBJ) src/ui_html.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

src/ui_html.o: src/ui_html.c
	$(CC) $(CFLAGS) -c -o $@ $<

src/ui_html.c: web/ui.html
	@awk 'BEGIN{printf "/* generated from web/ui.html */\nconst char UI_HTML[] =\n"} \
	{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "\"%s\\n\"\n", $$0} \
	END{printf ";\n"}' web/ui.html > $@

src/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

test-json: $(OBJ) tests/jtest.c
	$(CC) $(CFLAGS) -o /tmp/jtest tests/jtest.c src/json.c src/util.c $(LIBS)
	/tmp/jtest

clean:
	rm -f wdttpanel src/*.o

.PHONY: clean test-json
