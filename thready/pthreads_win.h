// pthreads_win.h
//
// https://github.com/tylerneylon/thready
//
// A pthreads-similar wrapper around windows threading functions.
//

#pragma once

#ifndef _WIN32

#include <pthread.h>

#define pthread_rwlock_rdunlock pthread_rwlock_unlock
#define pthread_rwlock_wrunlock pthread_rwlock_unlock
#define pthread_mutex_release(x)

int pthread_mutex_is_locked(pthread_mutex_t *m);

#else

#include <windows.h>


///////////////////////////////////////////////////////////////////////////////
// Thread control.

typedef DWORD pthread_t;

int pthread_create(pthread_t *thread, void *attr, void *(*start_fn)(void *), void *arg);
void pthread_exit(void *exit_value);
#define pthread_self GetCurrentThreadId


///////////////////////////////////////////////////////////////////////////////
// Mutex.

#define pthread_mutex_t CRITICAL_SECTION

// TODO This is convenient but bad practice.
//      Replace it with a function so we can properly wrap the windows way.
#define PTHREAD_MUTEX_INITIALIZER {(void*)-1,-1,0,0,0,0}

// All values `m` here have type `pthread_mutex_t *`.
// The attr parameter to pthread_mutex_init is expected to be NULL.
#define pthread_mutex_init(m, attr) InitializeCriticalSection(m)
#define pthread_mutex_lock(m) EnterCriticalSection(m)
#define pthread_mutex_unlock(m) LeaveCriticalSection(m)
#define pthread_mutex_destroy(m) DeleteCriticalSection(m)

// Not an actual pthreads function. The return value is reliable when:
// This returns true & you own the lock: this will remain the case.
// This returns false: someone else may lock it, but you know your thread
// doesn't have the lock.
int pthread_mutex_is_locked(pthread_mutex_t *m);

// Note: pthread_mutex_release is not actually a pthreads function, but seems
// to be required for the windows implementation.


///////////////////////////////////////////////////////////////////////////////
// Condition variable.

#define pthread_cond_t CONDITION_VARIABLE
#define PTHREAD_COND_INITIALIZER {0}

void pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
void pthread_cond_signal(pthread_cond_t *cond);


///////////////////////////////////////////////////////////////////////////////
// Read-write lock.

#define pthread_rwlock_t SRWLOCK
#define PTHREAD_RWLOCK_INITIALIZER SRWLOCK_INIT

#define pthread_rwlock_wrlock(lock) AcquireSRWLockExclusive(lock)
#define pthread_rwlock_rdlock(lock) AcquireSRWLockShared(lock)
#define pthread_rwlock_wrunlock(lock) ReleaseSRWLockExclusive(lock)
#define pthread_rwlock_rdunlock(lock) ReleaseSRWLockShared(lock)

// The two unlock functions are not actually pthreads functions. They are
// modifications to simplify the windows wrapper implementation. 


///////////////////////////////////////////////////////////////////////////////
// One-time initialization.

#define pthread_once_t INIT_ONCE
#define PTHREAD_ONCE_INIT INIT_ONCE_STATIC_INIT

void pthread_once(pthread_once_t *once_control, void(*init)());

#endif