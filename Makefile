CC_X64	:= x86_64-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -Wl,-TSectionLink.ld
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= bootlicker.x64.exe
BINX64	:= bootlicker.x64.bin

USERSC	:= $(wildcard usermode/*.c)
USEROB	:= $(USERSC:%.c=%.o)

BOOTSC	:= $(wildcard bootkit/*.c)
BOOTOB	:= $(BOOTSC:%.c=%.o)

KERNSC	:= $(wildcard kernel/*.c)
KERNOB	:= $(KERNSC:%.c=%.o)

CORESC	:= $(wildcard core/*.c)
COREOB	:= $(CORESC:%.c=%.o)

##
## Build the bootlicker shellcode
##
all: $(BOOTOB) $(KERNOB) $(COREOB) $(USEROB)
	@ nasm -f win64 asm/x64/GetIp.asm -o obj/GetIp.x64.o
	@ $(CC_X64) $(CFLAGS) $(LFLAGS) obj/*.o -o $(OUTX64)
	@ python3 python3/extract.py -f $(OUTX64) -o $(BINX64)

##
## Build all the usermode object files
##
$(USEROB):
	@ $(CC_X64) -o obj/usermode_$(basename $(notdir $@)).o -c $(basename $@).c $(CFLAGS) -Iinclude

##
## Build all the bootkit object files
##
$(BOOTOB):
	@ $(CC_X64) -o obj/bootkit_$(basename $(notdir $@)).o -c $(basename $@).c $(CFLAGS) -Iinclude

##
## Build all the kernel object files
##
$(KERNOB):
	@ $(CC_X64) -o obj/kernel_$(basename $(notdir $@)).o -c $(basename $@).c $(CFLAGS) -Iinclude -Iinclude/ddk

##
## Build all the core object files
##
$(COREOB):
	@ $(CC_X64) -o obj/core_$(basename $(notdir $@)).o -c $(basename $@).c $(CFLAGS) -Iinclude

clean:
	rm -rf obj/*.o
	rm -rf *.exe
	rm -rf *.bin
