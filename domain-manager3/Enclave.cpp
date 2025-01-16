
/*syscall test in eyrie rt*/

/*

mmap
munmap
mprotect
pthread_create


int pkey_mprotect(void *ptr, size_t len, int prot, int pkey)
{
    printf("Syscall: pkey_mprotect(%p, %zu, %d, %d)\n", ptr, len, prot, pkey);
    return syscall(SYS_pkey_mprotect, ptr, len, prot, pkey);
}

int pkey_alloc(unsigned int flags, unsigned int access_rights)
{
    printf("Syscall: pkey_alloc(%u, %u)\n", flags, access_rights);
    int ret = syscall(SYS_pkey_alloc, flags, access_rights);
    if (-1 == ret) {
      errno = ENOSPC; // just guessing
    }
    printf("Syscall: pkey_alloc(%u, %u). ret = %d\n", flags, access_rights, ret);
    return ret;
}

int pkey_free(int pkey)
{
    printf("Syscall: pkey_free(%d)\n", pkey);
    int ret = syscall(SYS_pkey_free, pkey);
    if (-1 == ret) {
      errno = EINVAL;
    }
    return ret;
}
// --------------------------------------------

void run_pre_init_tests() {
  // Before initialization, all calls shall work as usual
  int ret;
  int pkey = pkey_alloc(0, 0);
  assert(pkey >= 0);
  char* mem = mmap(NULL, 2 * PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  assert(MAP_FAILED != mem);
  mem[1] = mem[0]+1;
  ret = mprotect(mem, PAGESIZE, PROT_READ | PROT_WRITE);
  assert(0 == ret);
  ret = pkey_mprotect(mem + PAGESIZE, PAGESIZE, PROT_READ | PROT_WRITE, pkey);
  assert(0 == ret);
  ret = munmap(mem, 2 * PAGESIZE);
  assert(0 == ret);
  ret = pkey_free(pkey);
  assert(0 == ret);
}

//------------------------------------------

#define PATTERN1 0xAFFEAFFE
#define PATTERN2 0xDEADBEEF
#define PATTERN3 0xC0FFFFEE

void* pthread_test1(void* arg) {
    printf("I am thread 1: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var++;
      sched_yield();
    }
    printf("thread1 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void* pthread_test2(void* arg) {
    printf("I am thread 2: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=7;
      sched_yield();
    }
    printf("thread2 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void* pthread_test3(void* arg) {
    printf("I am thread 3: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=5;
      sched_yield();
    }
    printf("thread3 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void test4_pthread() {
  int ret;
  printf("TEST4\n");
  pthread_t thread1, thread2, thread3;
  ret = pthread_create(&thread1, NULL, pthread_test1, (void*)PATTERN1);
  assert(ret == 0);
  ret = pthread_create(&thread2, NULL, pthread_test2, (void*)PATTERN2);
  assert(ret == 0);
  ret = pthread_create(&thread3, NULL, pthread_test3, (void*)PATTERN3);
  assert(ret == 0);
  printf("Main waiting for other thread");

  uintptr_t retval;
  ret = pthread_join(thread3, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN3+1000*5);

  ret = pthread_join(thread2, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN2+1000*7);

  ret = pthread_join(thread1, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN1+1000);

  printf("Main done waiting");
}
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <syscall.h>
#include <pthread.h>
#include <assert.h>
#include <sched.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>


#define PAGESIZE 4096
#define SYS_pkey_mprotect 288
#define SYS_pkey_alloc 289
#define SYS_pkey_free 290

#define PATTERN1 0xAFFEAFFE
#define PATTERN2 0xDEADBEEF
#define PATTERN3 0xC0FFFFEE

void* pthread_test1(void* arg) {
    printf("I am thread 1: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var++;
      sched_yield();
    }
    printf("thread1 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void* pthread_test2(void* arg) {
    printf("I am thread 2: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=7;
      sched_yield();
    }
    printf("thread2 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void* pthread_test3(void* arg) {
    printf("I am thread 3: %p\n", arg);
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=5;
      sched_yield();
    }
    printf("thread3 returning %lx", var);
    return (void*)var; // same as pthread_exit
}

void test4_pthread() {
  int ret;
  printf("TEST4\n");
  pthread_t thread1, thread2, thread3;
  ret = pthread_create(&thread1, NULL, pthread_test1, (void*)PATTERN1);
  assert(ret == 0);
  ret = pthread_create(&thread2, NULL, pthread_test2, (void*)PATTERN2);
  assert(ret == 0);
  ret = pthread_create(&thread3, NULL, pthread_test3, (void*)PATTERN3);
  assert(ret == 0);
  printf("Main waiting for other thread");

  uintptr_t retval;
  ret = pthread_join(thread3, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN3+1000*5);

  ret = pthread_join(thread2, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN2+1000*7);

  ret = pthread_join(thread1, (void*)&retval);
  assert(ret == 0);
  printf("retval = %lx", retval);
  assert(retval == PATTERN1+1000);

  printf("Main done waiting");
}

int pkey_mprotect(void *ptr, size_t len, int prot, int pkey)
{
    printf("Syscall: pkey_mprotect(%p, %zu, %d, %d)\n", ptr, len, prot, pkey);
    return syscall(SYS_pkey_mprotect, ptr, len, prot, pkey);
}

int pkey_alloc(unsigned int flags, unsigned int access_rights)
{
    printf("Syscall: pkey_alloc(%u, %u)\n", flags, access_rights);
    int ret = syscall(SYS_pkey_alloc, flags, access_rights);
    if (-1 == ret) {
      errno = ENOSPC; // just guessing
    }
    printf("Syscall: pkey_alloc(%u, %u). ret = %d\n", flags, access_rights, ret);
    return ret;
}

int pkey_free(int pkey)
{
    printf("Syscall: pkey_free(%d)\n", pkey);
    int ret = syscall(SYS_pkey_free, pkey);
    if (-1 == ret) {
      errno = EINVAL;
    }
    return ret;
}

void run_pkey_tests_syscall() {
  // Before initialization, all calls shall work as usual
  int ret;
  int pkey = pkey_alloc(0, 0);
  assert(pkey >= 0);
  char* mem = mmap(NULL, 2 * PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  assert(MAP_FAILED != mem);
  mem[1] = mem[0]+1;
  ret = mprotect(mem, PAGESIZE, PROT_READ | PROT_WRITE);
  assert(0 == ret);
  ret = pkey_mprotect(mem + PAGESIZE, PAGESIZE, PROT_READ | PROT_WRITE, pkey);
  assert(0 == ret);
  ret = munmap(mem, 2 * PAGESIZE);
  assert(0 == ret);
  ret = pkey_free(pkey);
  assert(0 == ret);
}

int main(){

    printf("test syscall in eyrie start\n");
    run_pkey_tests_syscall();
    printf("pkey syscall test end\n");
    test4_pthread();
    printf("test syscall in eyrie end\n");
    return 0;
}