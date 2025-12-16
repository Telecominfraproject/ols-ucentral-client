# Production build system for uCentral client
# Configuration parser tests have been moved to tests/config-parser/Makefile
# Unit tests remain here for backward compatibility with original repository structure.
# See TESTING_FRAMEWORK.md for complete test documentation.

.PHONY: test

export CFLAGS+= -Werror -Wall -Wextra

ifeq ($(UCENTRAL_PLATFORM),)
PLATFORM := brcm-sonic
else
PLATFORM := ${UCENTRAL_PLATFORM}
endif

all: ucentral-client

platform/plat.a:
	$(MAKE) -C platform/${PLATFORM}
	cp platform/${PLATFORM}/plat.a platform/

%.o: %.c
	gcc -c -o $@ ${CFLAGS} -I ./ -I ./include $^

ucentral-client: ucentral-client.o proto.o platform/plat.a \
				 ucentral-json-parser.o ucentral-log.o router-utils.o base64.o
	g++ -o $@ $^ -lcurl -lwebsockets -lcjson -lssl -lcrypto -lpthread -ljsoncpp -lresolv

test:
	@echo "========= running unit tests  ========="
	$(MAKE) test-ucentral-json-parser
	@echo "========= unit tests completed ========"

test-ucentral-json-parser: test-ucentral-json-parser.o ucentral-json-parser.o
	g++ -o $@ $^ -lwebsockets -lcjson
	./test-ucentral-json-parser 2>/dev/null

clean:
	rm -f ucentral-client *.o test-ucentral-json-parser 2>/dev/null
	$(MAKE) -C platform/${PLATFORM} clean
