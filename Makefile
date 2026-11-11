## Compilation

CC = gcc
VERSION = $(shell grep '^version=' metapkg | cut -d= -f2)

TUNDRA_ICEWALL_DIR ?= /etc/tundra/icewall

TUNDRA_STD  = -std=c11
TUNDRA_DEFS = -D_GNU_SOURCE -DTUNDRA_ICEWALL_VERSION=\"$(VERSION)\" \
              -DTUNDRA_ICEWALL_DIR=\"$(TUNDRA_ICEWALL_DIR)\"
TUNDRA_INC  = -Isrc
TUNDRA_LIBS = -lseccomp -ltundra-conf

# Development: a checkout of tundra-libconf next to this one, built, is used
# instead of an installed library.
CONF_DEV ?= $(wildcard ../tundra-libconf)
ifneq ($(CONF_DEV),)
CONF_BUILD   = $(abspath $(CONF_DEV))/build
TUNDRA_INC  += -I$(CONF_DEV)/include
TUNDRA_LIBS := -L$(CONF_BUILD) $(TUNDRA_LIBS)
TEST_RPATH   = -Wl,-rpath,$(CONF_BUILD)
endif

CFLAGS ?= -Wall -Wextra -O2

TARGET = tundra-icewall

BUILD = build
SRCS = $(wildcard src/*.c)
HDRS = $(wildcard src/*.h)
OBJS = $(SRCS:src/%.c=$(BUILD)/%.o)
DEPS = $(OBJS:.o=.d)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(TUNDRA_LIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CPPFLAGS) $(CFLAGS) $(TUNDRA_INC) $(TUNDRA_DEFS) -MMD -MP -c $< -o $@

-include $(DEPS)

$(OBJS): Makefile metapkg

clean:
	rm -rf $(BUILD) $(TARGET)


## Tests

TEST_BUILD = $(BUILD)/test
TEST_BIN = $(TEST_BUILD)/tundra-icewall
TEST_TOOLS = $(patsubst tests/tools/%.c,$(TEST_BUILD)/tools/%,$(wildcard tests/tools/*.c))
TEST_DEFS = -D_GNU_SOURCE -DTUNDRA_ICEWALL_VERSION=\"$(VERSION)-test\" \
            -DTUNDRA_ICEWALL_DIR=\"$(TUNDRA_ICEWALL_DIR)\"

$(TEST_BIN): FORCE
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(TUNDRA_INC) $(TEST_DEFS) -o $@ $(SRCS) $(TUNDRA_LIBS) $(TEST_RPATH)

$(TEST_BUILD)/tools/%: tests/tools/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) -D_GNU_SOURCE -o $@ $<

UNIT_FLAGS = -g -fsanitize=address,undefined -fno-omit-frame-pointer
UNIT_TESTS = $(patsubst tests/unit/%.c,$(TEST_BUILD)/unit/%,$(wildcard tests/unit/*.c))

$(TEST_BUILD)/unit/%: tests/unit/%.c tests/unit/test.h $(SRCS) $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(UNIT_FLAGS) $(TUNDRA_INC) -Itests/unit \
		$(TEST_DEFS) -o $@ $< $(TUNDRA_LIBS) $(TEST_RPATH)

check-unit: $(UNIT_TESTS)
	@rc=0; for t in $(UNIT_TESTS); do echo "# $$t"; $$t || rc=1; done; exit $$rc

check: check-unit $(TEST_BIN) $(TEST_TOOLS)
	@sh tests/net/run.sh

FORCE:

.PHONY: install uninstall clean check check-unit FORCE


## Installation

PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
UNITDIR ?= $(PREFIX)/lib/systemd/system

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)/LICENSE
	install -Dm644 data/000-template.rules $(DESTDIR)$(SYSCONFDIR)/tundra/icewall/000-template.rules
	install -Dm644 data/500-base.rules $(DESTDIR)$(SYSCONFDIR)/tundra/icewall/500-base.rules
	install -d $(DESTDIR)$(UNITDIR)
	sed 's|@BINDIR@|$(PREFIX)/bin|' data/tundra-icewall.service.in \
		>$(DESTDIR)$(UNITDIR)/tundra-icewall.service
	chmod 644 $(DESTDIR)$(UNITDIR)/tundra-icewall.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -rf $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)
	rm -f $(DESTDIR)$(UNITDIR)/tundra-icewall.service
