all: update_submodules mayo

MAYOCPATH = ../MAYO-C/src

# Define variables
MAYO_BUILD_TYPE ?= generic
ENABLE_PARAMS_DYNAMIC ?= ON
MVARIANT_S ?= "MAYO_1;MAYO_2;MAYO_3;MAYO_5"
INC_PLATFORM = src/generic
# Source files
SOURCE_FILES_COMMON_SYS = $(MAYOCPATH)/common/randombytes_system.c $(MAYOCPATH)/common/aes_c.c $(MAYOCPATH)/common/aes128ctr.c $(MAYOCPATH)/common/aes_neon.c $(MAYOCPATH)/common/fips202.c $(MAYOCPATH)/common/mem.c
SOURCE_FILES_MAYO = $(MAYOCPATH)/params.c $(MAYOCPATH)/arithmetic.c mayo_rain.c
HEADER_FILES_FOLDERS = -I$(MAYOCPATH)/../include -I$(MAYOCPATH)/common -I$(MAYOCPATH) -I$(MAYOCPATH)/generic -I.../mayo-c-sys -I../vole/conservative_bs

update_submodules:
	git submodule update --init ../MAYO-C


mayo: $(SOURCE_FILES_COMMON_SYS) $(SOURCE_FILES_MAYO)
	mkdir -p target/debug
#	TODO: make it such that the intermediate .o files are correctly saved in the 
#	target/mayo folder
	$(CC) -fPIC $(HEADER_FILES_FOLDERS) -I$(INC_PLATFORM) $(CFLAGS) -DENABLE_PARAMS_DYNAMIC=$(ENABLE_PARAMS_DYNAMIC) -c $(SOURCE_FILES_COMMON_SYS) $(SOURCE_FILES_MAYO)
	gcc -shared -o target/debug/libmayo.so *.o
	rm *.o

