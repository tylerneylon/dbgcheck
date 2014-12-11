// dbgcheck_test.c
//
// https://github.com/tylerneylon/dbgcheck
//
// For testing the dbgcheck library.
//

#include "dbgcheck/dbgcheck.h"

// TODO Check if I need all of the preprocessor directives below.

#include "ctest.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include "winutil.h"
#endif

#pragma warning (disable : 4244)


////////////////////////////////////////////////////////////////////////////////
// Memory tests

int test_free_of_random_ptr() {
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

    // Being signaled is ok as we're still crashing at the point something
    // is going wrong. In the future I may want to do something in such
    // cases to provide clearer output about the file and line that caused
    // the signal.
    if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);
      test_that(sig == SIGSEGV || sig == SIGBUS);
      return test_success;  // We only get here if the above is true.
    }
    // If it wasn't a SIGSEGV, then the only acceptable exit case is
    // a non-signal exit code 1.
    test_that(WIFEXITED(status));
    test_that(WEXITSTATUS(status) == 1);
  } else {
    // Child code.

    // ctest sets up signal handlers, but we don't want them here.
    // We want bad memory access signals to kill us.
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS,  SIG_DFL);

    // This should cause the process to exit with status 1.
    dbgcheck__free((void *)(intptr_t)0x123, "my_set_name");

    // It's bad if we get here; exit with status 0 to let the parent know.
    exit(0);
  }
  return test_success;
}


////////////////////////////////////////////////////////////////////////////////
// Main

int main(int argc, char **argv) {
  set_verbose(0);  // Set this to 1 to help debug tests.

  start_all_tests(argv[0]);
  run_tests(
    test_free_of_random_ptr
  );
  return end_all_tests();
}
