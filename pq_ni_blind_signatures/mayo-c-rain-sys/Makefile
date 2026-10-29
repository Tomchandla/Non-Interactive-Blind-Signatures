all: update_submodules mayo

MAYOCPATH = ../MAYO-C/src
VOLEPATH = ../vole/conservative_bs
VOLELIB = ../vole-rainhash-then-mayo-sys/target/debug

# Define variables
ENABLE_PARAMS_DYNAMIC ?= ON

# Source files
SOURCE_FILES_COMMON_SYS = $(MAYOCPATH)/common/randombytes_system.c $(MAYOCPATH)/common/aes_c.c $(MAYOCPATH)/common/aes128ctr.c $(MAYOCPATH)/common/aes_neon.c $(MAYOCPATH)/common/fips202.c $(MAYOCPATH)/common/mem.c
SOURCE_FILES_MAYO = $(MAYOCPATH)/params.c $(MAYOCPATH)/arithmetic.c mayo_rain.c
HEADER_FILES_FOLDERS = -I$(MAYOCPATH)/../include -I$(MAYOCPATH)/common -I$(MAYOCPATH) -I$(MAYOCPATH)/generic -I$(VOLEPATH)

.PHONY: all update_submodules mayo clean

update_submodules:
	@test -f $(MAYOCPATH)/mayo.c || git submodule update --init ../MAYO-C

mayo:
	mkdir -p target/debug
	$(CC) -shared -fPIC $(HEADER_FILES_FOLDERS) $(CFLAGS) -DENABLE_PARAMS_DYNAMIC=$(ENABLE_PARAMS_DYNAMIC) $(SOURCE_FILES_COMMON_SYS) $(SOURCE_FILES_MAYO) -o target/debug/libmayo.so -L$(VOLELIB) -lconsv_bs_rainhash

clean:
	rm -f target/debug/libmayo.so
