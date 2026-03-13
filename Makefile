# SPDX-FileCopyrightText: 2026 Zygmunt Krynicki
# SPDX-License-Identifier: LGPL-3.0-only

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11 -fPIC
# glibc NSS modules are loaded as libnss_<service>.so.2 on modern systems,
# so both soname and output filename must use the .so.2 suffix.
LDFLAGS ?= -shared -Wl,-soname,libnss_snapd.so.2
CLANG_FORMAT ?= clang-format
INSTALL ?= install
MKDIR_P ?= mkdir -p

prefix ?= /usr/local
exec_prefix ?= $(prefix)
libdir ?= $(exec_prefix)/lib
DESTDIR ?=

TARGET := libnss_snapd.so.2
SRC := nss_snapd.c
OBJ := $(SRC:.c=.o)
MAP := nss_snapd.map
INSTALL_LIB := $(DESTDIR)$(libdir)/$(TARGET)
INSTALL_LIBDIR := $(DESTDIR)$(libdir)

TEST_BIN := test_nss_snapd
TEST_SRC := test_nss_snapd.c
REQUIRED_SYMBOLS := \
	_nss_snapd_getpwnam_r \
	_nss_snapd_getpwuid_r \
	_nss_snapd_setpwent \
	_nss_snapd_getpwent_r \
	_nss_snapd_endpwent \
	_nss_snapd_getgrnam_r \
	_nss_snapd_getgrgid_r \
	_nss_snapd_setgrent \
	_nss_snapd_getgrent_r \
	_nss_snapd_endgrent

.PHONY: all clean check check-symbols fmt install

all: $(TARGET)

$(TARGET): $(OBJ) $(MAP)
	$(CC) $(LDFLAGS) -Wl,--version-script=$(MAP) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): $(TEST_SRC) $(SRC)
	$(CC) -O2 -Wall -Wextra -Werror -std=c11 $(TEST_SRC) $(SRC) -o $(TEST_BIN)

check: $(TARGET) check-symbols $(TEST_BIN)
	./$(TEST_BIN)

check-symbols: $(TARGET)
	@set -eu; \
	exported_symbols="$$(nm -D --defined-only $(TARGET) | awk '{print $$3}' | sort -u)"; \
	for symbol in $(REQUIRED_SYMBOLS); do \
		printf '%s\n' "$$exported_symbols" | grep -qx "$$symbol" || { \
			echo "Missing exported symbol: $$symbol" >&2; \
			exit 1; \
		}; \
	done; \
	for symbol in $$exported_symbols; do \
		case " $(REQUIRED_SYMBOLS) " in \
			*" $$symbol "*) ;; \
			*) echo "Unexpected exported symbol: $$symbol" >&2; exit 1 ;; \
		esac; \
	done

fmt:
	find . -type f -name '*.c' -print0 | xargs -0r $(CLANG_FORMAT) -i

install: $(INSTALL_LIB)

$(INSTALL_LIB): $(TARGET) | $(INSTALL_LIBDIR)
	$(INSTALL) -m 0755 $(TARGET) $@

$(INSTALL_LIBDIR):
	@if [ -n "$(DESTDIR)" ]; then \
		$(MKDIR_P) "$@"; \
	fi

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_BIN)
