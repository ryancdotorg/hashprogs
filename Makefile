export LANG=C LC_ALL=C

BINARIES = bin/allsum bin/dgstmv bin/hashln

override CFLAGS += -O2 -fPIC \
	-Wall -Wextra -pedantic \
	-std=gnu11 -ggdb

COMPILE = $(CC) $(CFLAGS)

.PHONY: all clean _clean _nop

all: $(BINARIES)

bin/allsum: obj/allsum.o obj/bnprintf.o obj/digestlist.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto -o $@

bin/dgstmv: obj/dgstmv.o obj/bnprintf.o obj/digestlist.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto -o $@

bin/hashln: obj/hashln.o obj/hexlify.o obj/digestlist.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto -o $@

# fallback build rules
obj/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@

lib/%.so: obj/%.o
	@mkdir -p $(@D)
	$(COMPILE) -shared $< -o $@

# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	rm -rf $(wildcard bin/*) $(wildcard obj/*.o) || /bin/true
_nop:
	@true
