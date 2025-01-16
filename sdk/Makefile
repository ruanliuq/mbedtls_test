
# PLATFORM is one of (riscv, x86_64)
PLATFORM ?= riscv

INSTALLDIR?=/usr/lib

LDLIBS+=-lpthread




# CCFLAGS+=-DDEBUG # not release ,we need release
# CCFLAGS+=-DONTPRINTANYTHING


# CCFLAGS+=-DTIMING
# LDLIBS+=-lm


CCFLAGS+=$(CF)
CCFLAGS += -I/home/rlq/fimitee/riscv64/sysroot/usr/include
		
CCFLAGS += -I/home/rlq/mbedtls/tf-psa-crypto/core

############################################################################################
CCFLAGS += -I/home/rlq/mbedtls/include \
           -I/home/rlq/mbedtls/tf-psa-crypto/drivers/builtin/include \
           -I/home/rlq/mbedtls/tf-psa-crypto/include
########################################################################
# RISC-V
########################################################################
ifeq ($(PLATFORM),riscv)

ifndef RISCV
$(error RISCV is not set)
endif

#SDKBASE?=$(realpath ../../ariane-sdk)/

PREFIX=$(RISCV)/bin/riscv64-unknown-linux-gnu-
ARCH=arch/riscv

# compiler selection for platform
AR=$(PREFIX)gcc-ar
CC=$(PREFIX)gcc
LD=$(PREFIX)ld
OD=$(PREFIX)objdump
OC=$(PREFIX)objcopy
GDB=$(PREFIX)gdb

LDFLAGS+=-L$(RISCV)/riscv64-unknown-linux-gnu/lib64/lp64d \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib64 \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib \






RUN=$(RISCV)/bin/spike
#RUNARGS=--isa=rv64imacn
RUNARGS=
DEBUGGER=$(RISCV)/bin/spike
#DEBUGARGS=--isa=rv64imacn -d
DEBUGARGS=-d

#CCFLAGS+=-mabi=lp64 -march=rv64imac
#CCFLAGS+=-mabi=lp64d -march=rv64imafdc

CCFLAGS+=-DFAKE_TLS_SWAP -DSYSCALL_SANDBOXING

CCFLAGS+=
RUN_DEPS=linux

#-#  RUN_BIN=$(SDKBASE)bbl


#fvisibility=hidden might help aviding GOT stuff
CCFLAGS+=-fvisibility=hidden

endif # PLATFORM=riscv
########################################################################

AWK=awk
LDSCRIPT=$(ARCH)/linker

# FLAGS FOR CC AND LD
#-#  -l include
###### CCFLAGS+=-I. -Ipk -Ipk/$(ARCH) -Iuser -Iuser/$(ARCH) -I../syscall_hook
CCFLAGS+=-I. -Idm -Itests 
CFLAGS+=-std=gnu11
CXXFLAGS+=-std=c++11
CCFLAGS+=-fPIC
CCFLAGS+=-Wall
CCFLAGS+=-Werror=implicit-function-declaration
CCFLAGS+=-Werror=pointer-arith
CCFLAGS+=-Werror=format
CCFLAGS+=-Wpointer-arith
CCFLAGS+=-Werror=int-conversion
CCFLAGS+=-pthread
#CCFLAGS+=-flto
CCFLAGS+=-g
#CCFLAGS+=-O3
#CCFLAGS+=-O
CCFLAGS+=-Os


#-# CCFLAGS+=-DADDITIONAL_DEBUG_CHECKS
CCFLAGS+=-DDEBUG__CSR

# shared 是动态库？

LDFLAGS+=-static # or alternatively sudo ln -s ${RISCV}/sysroot/lib/ld-linux-riscv64-lp64d.so.1 /lib
LDFLAGS += -L/home/rlq/mbedtls/library
LDLIBS += -lmbedcrypto -lmbedtls -lmbedx509 -lpthread -static



           
     
           

########################################################################
# 默认目标
MAIN = eapp
all: $(MAIN)

# 定义源文件目录
SRC_DIR = dm
TEST_DIR = tests
LDSCRIPT = ld/linker
BENCH_DIR = /home/rlq/mbedtls/programs/test
ENCRYPTION = /home/rlq/mbedtls/tf-psa-crypto/drivers/builtin/src

# 定义目标静态库文件
TARGET1 = libdm.a
TARGET2 = libdm-host.a
TEST = tests.a

# 定义 OBJECTS
OBJ1 = $(SRC_DIR)/dm_handler_generic.o $(SRC_DIR)/dm_handler_arch.o $(SRC_DIR)/dm_handler.o
OBJ2 = $(SRC_DIR)/host_handler_generic.o $(SRC_DIR)/syscall.o
TEST_OBJ = $(TEST_DIR)/main.o $(TEST_DIR)/test3_ecall.o $(BENCH_DIR)/encryptiondata.o $(BENCH_DIR)/mybenchmark.o

# 构建第一个静态库
$(TARGET1): $(OBJ1)
	$(AR) -crs $@ $^
	@echo -e "\e[32m   libdm.a compiled successfully \e[0m"

# 构建第二个静态库
$(TARGET2): $(OBJ2)
	$(AR) -crs $@ $^
	@echo -e "\e[32m   libdm-host.a compiled successfully \e[0m"

# 构建测试程序
$(TEST): $(TEST_OBJ)
	$(AR) -crs $@ $^
	@echo -e "\e[32m   tests.a compiled successfully \e[0m"

# 通用规则，从每个 .c 文件编译 .o 文件
%.o: %.c
	$(CC) $(CFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.cc
	$(CC) $(CXXFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.S
	$(CC) $(CCFLAGS) -c $^ -o $@



$(LDSCRIPT).ld:
	mkdir -p $(dir $(LDSCRIPT).%)
	$(LD) --verbose > $@.tmp
	@./patch_ld.sh $@.tmp
	@mv $@.tmp $@

$(MAIN): $(TARGET1) $(TARGET2) $(TEST) | $(LDSCRIPT).ld
	$(CC) -o $@ $(LDFLAGS) -Wl,-T $| -Wl,--start-group $^ -Wl,--end-group $(LDLIBS)

testapp: $(MAIN)
	@echo -e "\e[32m   test app compiled successfully \e[0m"
	@echo -e "\e[32m   all compiled successfully \e[0m"


clean:
	@rm -f $(OBJ1) $(OBJ2) $(TARGET1) $(TARGET2) $(TEST_OBJ) $(TEST) $(MAIN)
	@echo "completed"

.PHONY: all clean




