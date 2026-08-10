MAYOCPATH = ../MAYO-C/src
VOLEPATH = ../vole/conservative_bs

MAYO_BUILD_TYPE ?= generic
ENABLE_PARAMS_DYNAMIC ?= ON
WITH_RAINHASH ?= ON
MVARIANT_S ?= "MAYO_1;MAYO_2;MAYO_3;MAYO_5"

INC_PLATFORM = src/generic
OBJDIR = target/obj
LIBDIR = target/debug
LIB = $(LIBDIR)/libmayo.so

SOURCE_FILES_COMMON_SYS = \
	$(MAYOCPATH)/common/randombytes_system.c \
	$(MAYOCPATH)/common/aes_c.c \
	$(MAYOCPATH)/common/aes128ctr.c \
	$(MAYOCPATH)/common/aes_neon.c \
	$(MAYOCPATH)/common/fips202.c \
	$(MAYOCPATH)/common/mem.c

SOURCE_FILES_MAYO = \
	$(MAYOCPATH)/params.c \
	$(MAYOCPATH)/arithmetic.c \
	mayo_rain.c

SOURCES = $(SOURCE_FILES_COMMON_SYS) $(SOURCE_FILES_MAYO)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

vpath %.c . $(MAYOCPATH) $(MAYOCPATH)/common

HEADER_FILES_FOLDERS = \
	-I$(MAYOCPATH)/../include \
	-I$(MAYOCPATH)/common \
	-I$(MAYOCPATH) \
	-I$(MAYOCPATH)/generic \
	-I$(VOLEPATH) \
	-I$(INC_PLATFORM)

DEFINES = -DENABLE_PARAMS_DYNAMIC=$(ENABLE_PARAMS_DYNAMIC)
ifeq ($(WITH_RAINHASH),ON)
DEFINES += -DWITH_RAINHASH
endif

ALL_CFLAGS = -fPIC $(HEADER_FILES_FOLDERS) $(DEFINES) $(CFLAGS)

.PHONY: all mayo update_submodules clean
.DEFAULT_GOAL := all

all: update_submodules mayo

mayo: $(LIB)

$(LIB): $(OBJECTS) | $(LIBDIR)
	$(CC) -shared -o $@ $(OBJECTS) $(LDFLAGS)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(OBJDIR) $(LIBDIR):
	mkdir -p $@

update_submodules:
	@if [ ! -f $(MAYOCPATH)/mayo.c ]; then \
		git submodule update --init ../MAYO-C; \
	fi

clean:
	rm -rf $(OBJDIR) $(LIB)
