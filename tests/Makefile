# tests/Makefile — unit + integration harness (make test / make test-asan)
ROOT := ..
INC  := -I$(ROOT)/src -I$(ROOT)/third_party/bearssl/inc -I$(ROOT)/third_party/jsmn
BASE := -std=c99 -Wall -Wextra -Wno-unused-parameter -g -O1 \
        -D_GNU_SOURCE -D_DEFAULT_SOURCE -DBR_USE_URANDOM $(INC)
ifeq ($(ASAN),1)
BASE += -fsanitize=address,undefined -fno-omit-frame-pointer
SANLDFLAGS := -fsanitize=address,undefined
else
SANLDFLAGS :=
endif

OBJS := $(filter-out $(ROOT)/build/src/main.o,$(wildcard $(ROOT)/build/src/*.o)) \
        $(shell find $(ROOT)/build/third_party -name '*.o' | sort)

.PHONY: run unit clean

unit: build/unit

build/unit: unit.c $(OBJS)
	@mkdir -p build
	$(CC) $(BASE) unit.c $(OBJS) $(SANLDFLAGS) -o $@

build/redirect.so: redirect.c
	@mkdir -p build
	$(CC) -std=c99 -fPIC -shared -D_GNU_SOURCE redirect.c -o $@ -ldl

run: unit build/redirect.so
	@sh ./run.sh $(if $(ASAN),ASAN,NORMAL)

clean:
	rm -rf build tmp/*
