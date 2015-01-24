// dbgcheck_test.c
//
// https://github.com/tylerneylon/dbgcheck
//
// For testing the dbgcheck library.
//
// Some of these tests could theoretically give false failures, meaning that
// they may report something is wrong when the code being tested is actually
// ok. Specifically, these tests sometimes simply call sleep or usleep to let
// other threads do their thing. There is not technically a guarantee that the
// other threads will finish doing their thing in the given time. In practice,
// however, I would be surprised if this ever actually happens.
//

#include "dbgcheck/dbgcheck.h"

// TODO Check if I need all of the preprocessor directives below.

#include "ctest.h"
#include "thready/pthreads_win.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include "winutil.h"
#endif

#pragma warning (disable : 4244)


////////////////////////////////////////////////////////////////////////////////
// Test callback utility

// Definitions for use with test_callback.
typedef void (*Callback)();

const int sig_is_ok     = 1;
const int sig_is_not_ok = 0;

const int expect_success = 0;
const int expect_failure = 1;

#define test_callback(sigflag, status, cb) \
        test_callback_(sigflag, status, cb, #cb)

// This calls the callback in an isolated environment and:
//  1. If is_sig_ok is nonzero, the test passes if the callback exits due to
//     either SIGSEGV or SIGBUS (memory errors).
//  2. If the callback exits normally with expected_status, the test passes.
//  In any other case, the test fails.
int test_callback_(int is_sig_ok, int expected_status,
                   Callback callback, const char *callback_name) {

  test_printf("Running %s\n", callback_name);

  int retval = fork();
  if (retval == -1) {
    test_failed("fork failed with error: %s\n", strerror(errno));
  }
  if (retval) {

    // Parent code.
    int status;
    if (wait(&status) == -1) {
      test_failed("wait failed with error: %s\n", strerror(errno));
    }

    if (is_sig_ok) {
      if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        test_that(sig == SIGSEGV || sig == SIGBUS);
        return test_success;  // We only get here if the above is true.
      }
    } else if (WIFSIGNALED(status)) {
      test_printf("Signal-not-ok but child was killed via signal %d\n",
          WTERMSIG(status));
    }

    test_that(WIFEXITED(status));
    test_that(WEXITSTATUS(status) == expected_status);

  } else {

    // Child code.

    // ctest sets up signal handlers, but we don't want them here.
    // We want bad memory access signals to kill us.
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS,  SIG_DFL);

    // Ignore stdout since we expect a passing test to generate
    // dbgcheck-origin error messages.
    FILE *f = freopen("/dev/null", "w", stdout);
    if (f == NULL) {
      printf("freopen failed with error: %s\n", strerror(errno));
      exit(0);
    }

    callback();

    exit(0);
  }

  return test_success;
}


////////////////////////////////////////////////////////////////////////////////
// Thread tests

void *do_same_thread_check(void *unused) {
  dbgcheck__same_thread();
  return NULL;
}

void disobey_same_thread() {
  // We'll make 10 threads and run the same function in all of them.
  pthread_t thread;
  for (int i = 0; i < 10; ++i) {
    pthread_create(&thread,
                   NULL,                  // default attributes
                   do_same_thread_check,  // callback
                   NULL);                 // parameter for the callback
  }
  // The same_thread check is asynchronous, so give dbgcheck a moment to
  // process things.
  usleep(1000 * 10);  // Sleep for 10 ms.
}

void obey_same_thread() {
  for (int i = 0; i < 10; ++i) {
    // NULL --> unused parameter required for a pthread callback
    do_same_thread_check(NULL);
  }
  // The same_thread check is asynchronous, so give dbgcheck a moment to
  // process things.
  usleep(1000 * 10);  // Sleep for 10 ms.
}

int test_same_thread() {
  test_callback(sig_is_not_ok, expect_failure, disobey_same_thread);
  test_callback(sig_is_not_ok, expect_success, obey_same_thread);
  return test_success;
}

void *run_w_sync_block(void *unused) {
  dbgcheck__start_sync_block("my sync block");
  return NULL;
}

void disobey_sync_block_in_one_thread() {
  // Violate a sync block in a single thread.
  dbgcheck__start_sync_block("1-thread block");
  dbgcheck__start_sync_block("1-thread block");
}

void disobey_sync_block_in_multiple_threads() {
  // We'll make 10 threads and run the same function in all of them.
  pthread_t thread;
  for (int i = 0; i < 10; ++i) {
    pthread_create(&thread,
                   NULL,              // default attributes
                   run_w_sync_block,  // callback
                   NULL);             // parameter for the callback
  }
  // Give the other threads a moment to run - otherwise we'll drop out
  // and (perhaps falsy) report no problem.
  usleep(1000 * 10);  // Sleep for 10 ms.
}

void obey_sync_blocks() {
  for (int i = 0; i < 10; ++i) {
    dbgcheck__start_sync_block("obeyed block");
    dbgcheck__in_sync_block("obeyed block");
    dbgcheck__end_sync_block("obeyed block");
  }
}

int test_sync_blocks() {
  test_callback(sig_is_not_ok, expect_failure,
                disobey_sync_block_in_one_thread);
  test_callback(sig_is_not_ok, expect_failure,
                disobey_sync_block_in_multiple_threads);
  test_callback(sig_is_not_ok, expect_success,
                obey_sync_blocks);
  return test_success;
}

void disobey_in_sync() {
  dbgcheck__in_sync_block("block");
}

void obey_in_sync() {
  dbgcheck__start_sync_block("block");
  dbgcheck__in_sync_block("block");
  dbgcheck__end_sync_block("block");
}

// Say bye bye bye to not knowing if we're in a sync block.
int test_in_sync() {
  test_callback(sig_is_not_ok, expect_failure, disobey_in_sync);
  test_callback(sig_is_not_ok, expect_success,    obey_in_sync);
  return test_success;
}

void get_lock_twice() {
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);  // NULL --> default attributes
  dbgcheck__lock(&lock);
  dbgcheck__lock(&lock);
  pthread_mutex_destroy(&lock);
  // The lock checks are asynchronous, so give dbgcheck a moment to
  // process things.
  usleep(1000 * 10);  // Sleep for 10 ms.
}

void unlock_without_lock() {
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);  // NULL --> default attributes
  dbgcheck__unlock(&lock);
  pthread_mutex_destroy(&lock);
  // The lock checks are asynchronous, so give dbgcheck a moment to
  // process things.
  usleep(1000 * 10);  // Sleep for 10 ms.
}

void *obtain_lock(void *lock) {
  dbgcheck__lock((pthread_mutex_t *)lock);
  return NULL;
}

void unlock_when_owned_by_other_thread() {

  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);  // NULL --> default attributes

  pthread_t thread;
  pthread_create(&thread,
                 NULL,         // default attributes
                 obtain_lock,  // callback
                 &lock);       // parameter for the callback

  // Give the other thread a moment to obtain the lock.
  usleep(1000 * 10);  // Sleep for 10 ms.

  // We expect dbgcheck to exit with status 1 here.
  dbgcheck__unlock(&lock);

  // The lock checks are asynchronous, so give dbgcheck a moment to
  // process things.
  usleep(1000 * 10);  // Sleep for 10 ms.
}


int test_locks() {
  test_callback(sig_is_not_ok, expect_failure, get_lock_twice);
  test_callback(sig_is_not_ok, expect_failure, unlock_without_lock);
  test_callback(sig_is_not_ok, expect_failure, unlock_when_owned_by_other_thread);
  return test_success;
}

////////////////////////////////////////////////////////////////////////////////
// Memory tests

void free_random_ptr() {
  // This should cause the process to exit due to a bad-memory signal.
  dbgcheck__free((void *)(intptr_t)0x123, "my_set_name");
}

int test_free_of_random_ptr() {
  return test_callback(sig_is_ok, expect_failure, free_random_ptr);
}

void use_bad_set_name_with_malloc() {
  void *ptr = dbgcheck__malloc(64, "set_name1");

  // This should cause the process to exit with status 1.
  dbgcheck__free(ptr, "set_name2");
}

void use_bad_set_name_with_calloc() {
  void *ptr = dbgcheck__calloc(64, "set_name1");

  // This should cause the process to exit with status 1.
  dbgcheck__free(ptr, "set_name2");
}

void use_bad_set_name_with_strdup() {
  void *ptr = dbgcheck__strdup("src string", "set_name1");

  // This should cause the process to exit with status 1.
  dbgcheck__free(ptr, "set_name2");
}

int test_bad_set_name() {
  test_callback(sig_is_not_ok, expect_failure, use_bad_set_name_with_malloc);
  test_callback(sig_is_not_ok, expect_failure, use_bad_set_name_with_calloc);
  test_callback(sig_is_not_ok, expect_failure, use_bad_set_name_with_strdup);

  // Any errors will be noticed before the return statement.
  return test_success;
}

void use_mem_ops_correctly() {
  void *ptr_from_malloc = dbgcheck__malloc(8, "from malloc");
  void *ptr_from_calloc = dbgcheck__calloc(8, "from calloc");
  test_that(*(char *)ptr_from_calloc == '\0');
  void *ptr_from_strdup = dbgcheck__strdup("hi", "from strdup");

  dbgcheck__free(ptr_from_malloc, "from malloc");
  dbgcheck__free(ptr_from_calloc, "from calloc");
  dbgcheck__free(ptr_from_strdup, "from strdup");
}

int test_correct_mem_usage() {
  return test_callback(sig_is_not_ok, expect_success, use_mem_ops_correctly);
}

void make_check_ptr_fail_by_bad_ptr() {
  void *ptr = dbgcheck__malloc(8, "void");
  dbgcheck__ptr(ptr + 1, "void");
}

void make_check_ptr_fail_by_bad_set_name() {
  void *ptr = dbgcheck__malloc(8, "set_name1");
  dbgcheck__ptr(ptr, "set_name2");
}

int test_check_ptr() {
  test_callback(sig_is_ok, expect_failure, make_check_ptr_fail_by_bad_ptr);
  test_callback(sig_is_not_ok, expect_failure,
      make_check_ptr_fail_by_bad_set_name);
  return test_success;
}

void double_free() {
  void *ptr = dbgcheck__malloc(8, "void");
  dbgcheck__free(ptr, "void");
  dbgcheck__free(ptr, "void");

  // The current double-free check is asynchronous, and if we don't give
  // the checking thread a chance to perform the check, this end-of-function
  // will exit the process with status 0 (via the test_callback wrapper).
  // So let's give the other thread a second to perform the check.
  sleep(1);
}

int test_double_free() {
  return test_callback(sig_is_not_ok, expect_failure, double_free);
}

void use_bad_ptr_size() {
  void *ptr = dbgcheck__malloc(8, "void");
  dbgcheck__ptr_size(ptr, "void", 9);
}

void use_good_ptr_size() {
  void *ptr = dbgcheck__malloc(8, "void");
  dbgcheck__ptr_size(ptr, "void", 8);
}

int test_ptr_size() {
  test_callback(sig_is_not_ok, expect_failure, use_bad_ptr_size);
  test_callback(sig_is_not_ok, expect_success, use_good_ptr_size);
  return test_success;
}

void use_bad_inner_ptr() {
  void *root_ptr  = dbgcheck__malloc(8, "void");
  void *inner_ptr = root_ptr + 10;
  dbgcheck__inner_ptr(inner_ptr, root_ptr, "void");
}

void use_good_inner_ptr() {
  void *root_ptr  = dbgcheck__malloc(8, "void");
  void *inner_ptr = root_ptr + 2;
  dbgcheck__inner_ptr(inner_ptr, root_ptr, "void");

  // This case should still be ok as end-of-buffer pointers are ok.
  inner_ptr = root_ptr + 8;
  dbgcheck__inner_ptr(inner_ptr, root_ptr, "void");
}

void use_bad_inner_ptr_size() {
  void *root_ptr  = dbgcheck__malloc(8, "void");
  void *inner_ptr = root_ptr + 2;
  dbgcheck__inner_ptr_size(inner_ptr, root_ptr, "void", 8);
}

void use_good_inner_ptr_size() {
  void *root_ptr  = dbgcheck__malloc(8, "void");
  void *inner_ptr = root_ptr + 2;
  dbgcheck__inner_ptr_size(inner_ptr, root_ptr, "void", 6);
}

int test_inner_ptr_checks() {
  test_callback(sig_is_not_ok, expect_failure, use_bad_inner_ptr);
  test_callback(sig_is_not_ok, expect_success, use_good_inner_ptr);
  test_callback(sig_is_not_ok, expect_failure, use_bad_inner_ptr_size);
  test_callback(sig_is_not_ok, expect_success, use_good_inner_ptr_size);
  return test_success;
}


////////////////////////////////////////////////////////////////////////////////
// General condition (fail_if) tests

void check_good_condition() {
  dbgcheck__fail_if(0, "This should not fail.\n");
}

void check_bad_condition() {
  dbgcheck__fail_if(1, "This should always fail.\n");
}

int test_fail_if() {
  test_callback(sig_is_not_ok, expect_success, check_good_condition);
  test_callback(sig_is_not_ok, expect_failure, check_bad_condition);
  return test_success;
}


////////////////////////////////////////////////////////////////////////////////
// Information tests

int test_bytes_used() {
  void *mem1 = dbgcheck__malloc(100, "abc");
  void *mem2 = dbgcheck__calloc(100, "abc");
  void *mem3 = dbgcheck__strdup("123456789", "abc");

  long bytes_used = dbgcheck__bytes_used_by_set_name("abc");
  test_printf("Before any frees, bytes_used=%d\n", bytes_used);
  test_that(bytes_used == 210);

  bytes_used = dbgcheck__bytes_used_by_set_name("def");
  test_printf("For unused set_name, bytes_used=%d\n", bytes_used);
  test_that(bytes_used == 0);

  dbgcheck__free(mem1, "abc");
  bytes_used = dbgcheck__bytes_used_by_set_name("abc");
  test_printf("After a free of 100 bytes, bytes_used=%d\n", bytes_used);
  test_that(bytes_used == 110);
  return test_success;
}


////////////////////////////////////////////////////////////////////////////////
// Main

int main(int argc, char **argv) {
  set_verbose(0);  // Set this to 1 to help debug tests.

  start_all_tests(argv[0]);
  run_tests(
    // Thread tests
    test_same_thread, test_sync_blocks, test_in_sync, test_locks,
    // Memory tests
    test_free_of_random_ptr, test_bad_set_name, test_correct_mem_usage,
    test_check_ptr, test_double_free, test_ptr_size, test_inner_ptr_checks,
    // General condition tests
    test_fail_if,
    // Information tests
    test_bytes_used
  );
  return end_all_tests();
}
