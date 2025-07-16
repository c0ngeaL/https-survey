JSON_MODULE := $(shell perl -MJSON::XS -e 1 2>/dev/null && echo "JSON::XS" || echo "JSON::PP")
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I./src
LDFLAGS = -lssl -lcrypto -lresolv
TARGET = https-survey
TEST_TARGET = https-survey-test

# Source files
SRCS = src/scanner.c src/func.c
OBJS = $(SRCS:.c=.o)

# Test files
TEST_SRCS = test/test.c test/test-1.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

# is OpenSSL there?
PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)
ifdef PKG_CONFIG
  LDFLAGS += $(shell pkg-config --libs openssl)
  CFLAGS += $(shell pkg-config --cflags openssl)
  TEST_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs check)
else
  SSL_H := $(shell find /usr/include /usr/local/include -name openssl/ssl.h 2>/dev/null | head -n1)
  ifneq ($(SSL_H),)
    CFLAGS += -I$(dir $(SSL_H))/..
    TEST_LDFLAGS = $(LDFLAGS) -lcheck -pthread -lm -lrt -lsubunit
  else
    $(error "OpenSSL not found!")
  endif
endif

# Build rules
all: CFLAGS += -O2
all: $(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

coverage: CFLAGS += -fprofile-arcs -ftest-coverage --coverage
coverage: LDFLAGS += -lgcov --coverage
coverage: TEST_LDFLAGS += -lgcov --coverage
coverage: test

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): $(filter-out src/main.o, $(OBJS)) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

cov-report: coverage
	@echo "Using JSON module: $(JSON_MODULE)"
	lcov --ignore-errors negative --capture --directory . --output-file coverage.info
	lcov --ignore-errors negative --remove coverage.info '/usr/include/*' 'test/*' --output-file coverage.info
	genhtml coverage.info --output-directory coverage --quiet
	@echo "Coverage report generated at coverage/index.html"
clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET) *.gcda *.gcno *.gcov coverage.info
	rm -rf coverage

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all debug coverage test cov-report clean install uninstall
