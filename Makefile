# dbgcheck Makefile
#
# TODO Add nicer comments; build on cstructs Makefile as an example.
#

tests = out/dbgcheck_test

cstructs_obj = out/array.o out/map.o out/list.o

includes = -I.

ifeq ($(shell uname -s), Darwin)
	cflags = $(includes) -std=c99
else
	cflags = $(includes) -std=c99 -D _GNU_SOURCE
endif
cc = gcc $(cflags)

# Test-running environment.
testenv = DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MALLOC_LOG_FILE=/dev/null

all: out/dbgcheck.o $(tests)

test: $(tests)
	@echo Running tests:
	@echo -
	@for test in $(tests); do $(testenv) $$test || exit 1; done
	@echo -
	@echo All tests passed!

out/dbgcheck.o: dbgcheck/dbgcheck.c dbgcheck/dbgcheck.h | out
	$(cc) -o $@ -c $<

out/thready.o: thready/thready.c thready/thready.h | out
	$(cc) -o $@ -c $< -pthread

$(cstructs_obj) : out/%.o : cstructs/%.c cstructs/%.h | out
	$(cc) -o $@ -c $<

out/ctest.o : test/ctest.c test/ctest.h | out
	$(cc) -o $@ -c $<

$(tests) : out/% : test/%.c $(cstructs_obj) out/dbgcheck.o out/thready.o out/ctest.o | out
	$(cc) -o $@ $^ -pthread

out:
	mkdir out

clean:
	rm -rf out/

.PHONY: test
