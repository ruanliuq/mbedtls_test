README for Mbed TLS
===================
下载过来的是mbedtls_test重命名为mbedtls

mbedtls/domain-manager3/makefile文件需要修改

具体为带有rlq的路径都改为自己的

注意！！！！！！！！！
mbedtls/programs/test目录下，删除原来的benchmark.c，把benchmark-back（附件）.c重命名为benchmark.c

进入mbedtls目录下执行

make CC=riscv64-unknown-linux-gnu-gcc AR=riscv64-unknown-linux-gnu-ar LD=riscv64-unknown-linux-gnu-ld

大概率会出错，应该是找不到什么文件来着

先make clean

再make

等待编译成功，此时编译为的是x86架构的

再make clean

再make CC=riscv64-unknown-linux-gnu-gcc AR=riscv64-unknown-linux-gnu-ar LD=riscv64-unknown-linux-gnu-ld

应该就会通过了，不清楚原理

成功执行的话会在mbedtls/library目录下生成libmbedcrypto.a、libmbedtls.a、libmbedx509.a


mbedtls/build文件夹里面的东西都是没有用的，可以删除


修改需要执行的测试程序，进入mbedtls/programs/test/文件夹下的mybenchmark.c文件，见test_bench()函数，需要执行哪个就把哪个的注释去掉（如todo.hmac_drbg = 1;）

benchmark-back（附件）.c里面是原来的程序（没有动过），我把里面的进行修改和删除写的mybenchmark.c


最后再进入mbedtls/domain-manager3执行make clean和make


生成的eapp文件就可以用了





