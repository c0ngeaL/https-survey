CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I./src
TARGET = https-survey
SRCS = src/scanner.c src/func.c
OBJS = $(SRCS:.c=.o)
# is OpenSSL there?
PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)
ifdef PKG_CONFIG
  LDFLAGS += $(shell pkg-config --libs openssl)
  CFLAGS += $(shell pkg-config --cflags openssl)
else
  SSL_H := $(shell find /usr/include /usr/local/include -name openssl/ssl.h 2>/dev/null | head -n1)
  ifneq ($(SSL_H),)
    CFLAGS += -I$(dir $(SSL_H))/..
    LDFLAGS += -lssl -lcrypto
  else
    $(error "OpenSSL not found!")
  endif
endif

# Build rules
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJS) $(TARGET)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)
uninstall:
	rm -f /usr/local/bin/$(TARGET)
.PHONY: all clean install uninstall
