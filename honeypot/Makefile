MODULE_NAME = honeypot
MODULE_SRC = $(MODULE_NAME).c
MODULE_SO  = $(MODULE_NAME).so
REDIS_HEADER = redismodule.h
REDIS_HEADER_URL = https://raw.githubusercontent.com/redis/redis/7.2/src/$(REDIS_HEADER)

all: $(MODULE_SO)

$(REDIS_HEADER):
	@echo "> Downloading $(REDIS_HEADER)..."
	curl -s -O $(REDIS_HEADER_URL)

$(MODULE_SO): $(MODULE_SRC) $(REDIS_HEADER)
	gcc -Wall -fPIC -shared -o $(MODULE_SO) $(MODULE_SRC)
	@echo "> Build complete: $(MODULE_SO)"

clean:
	rm -f $(MODULE_SO) $(REDIS_HEADER)

.PHONY: all clean
