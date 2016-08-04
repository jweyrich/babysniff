#
# babysniff
#

PLATFORM_OS := $(shell uname)
PREFIX = /usr
DEST = $(DESTDIR)/$(PREFIX)/bin
LINK = $(CXX)
AR = ar cq
RANLIB = ranlib -s
RM = rm -f
RM_DIR = rm -rf
CHK_DIR_EXISTS = test -d
MKDIR = mkdir -p
INSTALL = install -m 0755
SHAREDIR = /usr/share/babysniff
MAN = ../doc/manpages
MANDIR = /usr/share/man/man1

OBJECTS_DIR	= build/obj
INCPATH		=

CFLAGS		+= $(INCPATH) -W -Wall -Wextra -std=c99 -pedantic -ggdb3 -O0
LDFLAGS		+= $(LIBS)

#LIBBASE = lib/libbase

babysniff_SOURCE_DIRS		= src src/compat src/proto src/proto/dns src/types
ifeq ($(PLATFORM_OS), Darwin)
	babysniff_SOURCE_DIRS	+= src/bsd
endif
ifeq ($(PLATFORM_OS), Linux)
	babysniff_SOURCE_DIRS	+= src/linux
endif
babysniff_SOURCE_FILTER	= $(wildcard $(dir)/*.c)
babysniff_SOURCES			= $(foreach dir, $(babysniff_SOURCE_DIRS), $(babysniff_SOURCE_FILTER))
babysniff_OBJECTS			= $(addprefix $(OBJECTS_DIR)/, $(addsuffix .o, $(basename ${babysniff_SOURCES})))
babysniff_INCPATH			= -I./src #-I$(LIBBASE)/include
babysniff_LIBS				= #$(LIBBASE)/libbase.a

PROGRAMS = babysniff
LIBRARIES =

####### Build rules

all: $(LIBRARIES) $(PROGRAMS)

babysniff: CPPFLAGS += -D_GNU_SOURCE=1 -DDEBUG
babysniff: INCPATH += $(babysniff_INCPATH)
babysniff: LIBS += $(babysniff_LIBS)
babysniff: $(babysniff_OBJECTS)
	$(LINK) -o $@ $(LDFLAGS) $^

$(OBJECTS_DIR)/%.o: %.c
	@echo 'Building file: $<'
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

install:
	test -d $(DEST) || mkdir -p $(DEST)
	for prog in $(PROGRAMS); do \
		$(INSTALL) $$prog $(DEST); \
		test -f $(MAN)/$$prog.1 && gzip -c -9 $(MAN)/$$prog.1 > $(MANDIR)/$$prog.1.gz || echo -n; \
	done
	test -d $(SHAREDIR) || mkdir -p $(SHAREDIR)

uninstall:
	for prog in $(PROGRAMS); do \
		$(RM) $(DEST)/$$prog; \
		$(RM) $(MANDIR)/$$prog.1.gz; \
	done

clean:
	$(RM_DIR) $(OBJECTS_DIR)
	$(RM) $(PROGRAMS) $(LIBRARIES)
