CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I./src -fprofile-arcs -ftest-coverage
TARGET = https-survey
TEST_TARGET = https-survey
SRCS = src/scanner.c src/func.c
OBJS = $(SRCS:.c=.o)
TEST_SRCS = test/test.c test/test-1.c
TEST_OBJS = $(TEST_SRCS:.c=.o) src/scanner.o
# is OpenSSL there?
PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)
ifdef PKG_CONFIG
  LDFLAGS += $(shell pkg-config --libs openssl)
  CFLAGS += $(shell pkg-config --cflags openssl)
  TEST_LDFLAGS += $(shell pkg-config --libs openssl check)
else
  SSL_H := $(shell find /usr/include /usr/local/include -name openssl/ssl.h 2>/dev/null | head -n1)
  ifneq ($(SSL_H),)
    CFLAGS += -I$(dir $(SSL_H))/..
  LDFLAGS = -lssl -lcrypto -lresolv -lgcov
TEST_LDFLAGS = -lssl -lcrypto -lresolv -lgcov -lcheck -pthread
  else
    $(error "OpenSSL not found!")
  endif
endif
# Build rules
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): $(OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

coverage: test
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage
	xdg-open coverage/index.html

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET) *.gcda *.gcno *.gcov coverage.info
	rm -rf coverage

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)
.PHONY: all test coverage clean install uninstall
