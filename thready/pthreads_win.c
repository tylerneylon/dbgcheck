// pthreads_win.c
//
// https://github.com/tylerneylon/thready
//
// In writing this, it was helpful for me to learn from this page:
// http://locklessinc.com/articles/pthreads_on_windows/
//

#include "pthreads_win.h"


#ifndef _WIN32

int pthread_mutex_is_locked(pthread_mutex_t *m) {
  if (pthread_mutex_trylock(m) == 0) {
    // We got the lock, so it must have been unlocked.
    pthread_mutex_unlock(m);
    return 0;  // It's unlocked.
  }
  return 1;  // We couldn't lock it, so it's locked.
}

#else

#include <process.h>


///////////////////////////////////////////////////////////////////////////////
// Internal types and functions.

typedef struct {
  void *(*start_fn)(void *);
  void *arg;
} StartCall;

static void thread_start(void *param) {
  StartCall *call = (StartCall *)param;
  // Copy over the values so we can free `call` before making the call.
  // Otherwise, if the thread exits without returning, we have a leak.
  void *(*start_fn)(void *) = call->start_fn;
  void *arg                 = call->arg;
  free(call);
  start_fn(arg);
}

static BOOL CALLBACK init_once(PINIT_ONCE once_control, PVOID param, PVOID *context) {
  void(*init)() = (void(*)())param;  // yikes
  init();
  return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
// Thread control.

int pthread_create(pthread_t *thread, void *attr, void *(*start_fn)(void *), void *arg) {
  StartCall *call = malloc(sizeof(StartCall));
  call->start_fn = start_fn;
  call->arg      = arg;

  uintptr_t handle = _beginthread(thread_start, 0, call);

  if (handle != -1) {
    *thread = GetThreadId((HANDLE)handle);
    return 0;
  }

  return -1;  // Indicate failure.
}

void pthread_exit(void *exit_value) {
  _endthread();
}


///////////////////////////////////////////////////////////////////////////////
// Mutex.

int pthread_mutex_is_locked(pthread_mutex_t *m) {

  // The following use of internal state is relatively safe. Source:
  // http://blogs.msdn.com/b/oldnewthing/archive/2014/09/11/10557052.aspx

  return m->LockCount != -1;  // -1 indicates an unlocked state.
}


///////////////////////////////////////////////////////////////////////////////
// Condition variable.

void pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
  SleepConditionVariableCS(cond, mutex, INFINITE);  // INFINITE --> timeout
}

void pthread_cond_signal(pthread_cond_t *cond) {
  WakeConditionVariable(cond);
}


///////////////////////////////////////////////////////////////////////////////
// One-time initialization.

void pthread_once(pthread_once_t *once_control, void(*init)()) {
  void **context = NULL;  // Optional output context that we don't use.
  InitOnceExecuteOnce(once_control, init_once, init, context);
}

#endif
