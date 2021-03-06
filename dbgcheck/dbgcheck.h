// dbgcheck.h
//
// https://github.com/tylerneylon/dbgcheck
//
// Sanity checks for threads, pointers, and general boolean conditions.
//
// This module adds zero functionality by default. Define the dbgcheck_on
// macro before including this header file to turn it on. The module can
// be turned on and off on a per-file basis.
//
// Usage example:
//
// #define dbgcheck_on
// #include "dbgcheck.h"
//
// // Then use things like dbgcheck__malloc instead of malloc, etc.
//

#pragma once


////////////////////////////////////////////////////////////////////////////////
// Preprocessor controls - e.g. turn dbgcheck on or off.

// TODO Check that this flag is obeyed, both on and off:
#define dbgcheck_die_on_failure

// When this is defined, it makes dbgcheck__same_thread slower and synchronous.
// This is good for setting a breakpoint to see what went wrong.
//#define dbgcheck_sync_same_thread


#ifdef dbgcheck_on

#include "thready/pthreads_win.h"
#include <stdlib.h>


////////////////////////////////////////////////////////////////////////////////
// Thread safety.

// This verifies that the line it's run on is always run in the same thread.
#define dbgcheck__same_thread() \
        dbgcheck__same_thread_(__FILE__, __LINE__)

// The next two functions work together to define code blocks that expect to
// never run concurrently. dbgcheck considers it a failure if it ever sees two
// blocks with the same name running concurrently. It expects the name values to
// be forever-living strings such as string literals.
#define dbgcheck__start_sync_block(name) \
        dbgcheck__start_sync_block_(name, __FILE__, __LINE__)

#define dbgcheck__end_sync_block(name) \
        dbgcheck__end_sync_block_(name, __FILE__, __LINE__)

#define dbgcheck__in_sync_block(name) \
        dbgcheck__in_sync_block_(name, __FILE__, __LINE__)

// These functions will notice if a thread tries to obtain a lock it already has
// or if it tries to release a lock it doesn't have.
#define dbgcheck__lock(mutex) \
        dbgcheck__lock_(mutex, __FILE__, __LINE__)

#define dbgcheck__unlock(mutex) \
        dbgcheck__unlock_(mutex, __FILE__, __LINE__)

// This function performs the same functionality as the above lock one,
// with the addition of building a directed graph of lock nesting orders. It's
// a "named" lock in that it expects to be called consistently with a single
// mutex variable owned within a single file.

#define dbgcheck__named_lock(mutex_var)                            \
        dbgcheck__named_lock_(&mutex_var, __FILE__ ":" #mutex_var, \
                              __FILE__, __LINE__)

// Intuition here: you *want* the nesting order mutex1 -> mutex2, meaning that
// either:
//  * mutex1-locked code wraps mutex2-locked code, or
//  * mutex1-unlocked code wraps mutex2-locked code.
// To be super-clear, the one thing to avoid is this:
//  * DO NOT let mutex1 be locked while mutex2 is already locked.
// All of these assertions are in the context of any single thread.
#define dbgcheck__dont_lock_x_when_y_locked(mutex_var1, mutex_var2)    \
        dbgcheck__dont_lock_x_when_y_locked_(__FILE__ ":" #mutex_var1, \
                                             __FILE__ ":" #mutex_var2)

////////////////////////////////////////////////////////////////////////////////
// Memory safety.

// This allocates memory blocks that may later be checked with dbgcheck__ptr and
// friends. Anything allocated with a given set name must be deallocated with
// dbgcheck__free using the same set name. Set names are arbitrary strings the
// user chooses; they are assumed to live indefinitely. Literals are great.
#define dbgcheck__malloc(size, set_name) \
        dbgcheck__malloc_(size, set_name, __FILE__, __LINE__)

// This is identical to dbgcheck__malloc except that it clears the memory by
// calling calloc instead of malloc.
#define dbgcheck__calloc(size, set_name) \
        dbgcheck__calloc_(size, set_name, __FILE__, __LINE__)

#define dbgcheck__strdup(src, set_name) \
        dbgcheck__strdup_(src, set_name, __FILE__, __LINE__)

#define dbgcheck__free(ptr, set_name) \
        dbgcheck__free_(ptr, set_name, __FILE__, __LINE__)

// This function is meant to work with root pointers, which are pointers
// pointing to an address directly returned by malloc and friends; a non-root
// pointer is one which points into, but not to the start of, a malloc'ed block.
// This verifies the integrity of the given pointer.  This can detect
// when a root pointer is being accessed after being freed, and is likely (but
// not guaranteed) to detect if a pointer has accidentally become non-root.
#define dbgcheck__ptr(root_ptr, set_name) \
        dbgcheck__ptr_(root_ptr, set_name, __FILE__, __LINE__)

// This performs the same checks as dbgcheck__ptr, as well as verifying that the
// given block has at least `size` bytes available.
#define dbgcheck__ptr_size(root_ptr, set_name, size) \
        dbgcheck__ptr_size_(root_ptr, set_name, size, __FILE__, __LINE__)

// This is similar to dbgcheck__ptr, except that it works with pointers which
// may or may not be root. It's expected that root_ptr points to the malloc'ed
// block into which inner_ptr points. If root_ptr is indeed a root pointer,
// this will detect if the block is already freed or if the inner_ptr now
// points outside the block it is meant to be within.
#define dbgcheck__inner_ptr(inner_ptr, root_ptr, set_name) \
        dbgcheck__inner_ptr_(inner_ptr, root_ptr, set_name, __FILE__, __LINE__)

#define dbgcheck__inner_ptr_size(inner_ptr, root_ptr, set_name, size)  \
        dbgcheck__inner_ptr_size_(inner_ptr, root_ptr, set_name, size, \
                                  __FILE__, __LINE__)


////////////////////////////////////////////////////////////////////////////////
// General checks and information.

#define dbgcheck__fail_if(cond, ...) \
        dbgcheck__fail_if_(cond, __FILE__, __LINE__, __VA_ARGS__)

#define dbgcheck__warn_if(cond, ...) \
        dbgcheck__warn_if_(cond, __FILE__, __LINE__, __VA_ARGS__)

long    dbgcheck__bytes_used_by_set_name(const char *set_name);

// Returns a string encoding the directed graph structure of the nested mutex
// lock behavior seen by dbgcheck. This is only generated for locks seen by
// dbgcheck via calls to dbgcheck__named_lock. The returned string is
// dynamically allocated, and owned by the caller.
char *dbgcheck__get_lock_graph_str();

// Publicly-visible functions that are meant to only be called by using the
// above macros.

void  dbgcheck__same_thread_(const char *file, int line);
void  dbgcheck__start_sync_block_(const char *name, const char *file, int line);
void  dbgcheck__end_sync_block_(const char *name, const char *file, int line);
void  dbgcheck__in_sync_block_(const char *name, const char *file, int line);

void  dbgcheck__lock_(pthread_mutex_t *mutex, const char *file, int line);
void  dbgcheck__unlock_(pthread_mutex_t *mutex, const char *file, int line);

void  dbgcheck__named_lock_(pthread_mutex_t *mutex, const char *mutex_name,
                            const char *file, int line);
void  dbgcheck__dont_lock_x_when_y_locked_(const char *mutex1_name,
                                           const char *mutex2_name);

void *dbgcheck__malloc_(size_t size, const char *set_name,
                        const char *file, int line);
void *dbgcheck__calloc_(size_t size, const char *set_name,
                        const char *file, int line);
char *dbgcheck__strdup_(const char *src, const char *set_name,
                        const char *file, int line);

void  dbgcheck__free_(void *ptr, const char *set_name,
                      const char *file, int line);
void  dbgcheck__ptr_(void *root_ptr, const char *set_name,
                     const char *file, int line);
void  dbgcheck__ptr_size_(void *ptr, const char *set_name,
                          size_t size, const char *file, int line);
void  dbgcheck__inner_ptr_(void *inner_ptr, void *root_ptr,
                           const char *set_name, const char *file, int line);
void  dbgcheck__inner_ptr_size_(void *inner_ptr, void *root_ptr,
                                const char *set_name, size_t size,
                                const char *file, int line);

void  dbgcheck__fail_if_(int cond, const char *file,
                         int line, const char *fmt, ...);
void  dbgcheck__warn_if_(int cond, const char *file,
                         int line, const char *fmt, ...);

#else

// When dbgcheck_on is left undefined, all macros default to as close to a no-op
// as we can get at compile time. The only macros that do any work are redefined
// as malloc, calloc, strdup, free, or pthread_mutex_[un]lock.

#define dbgcheck__same_thread()
#define dbgcheck__start_sync_block(name)
#define dbgcheck__end_sync_block(name)
#define dbgcheck__in_sync_block(name)
#define dbgcheck__lock(mutex) pthread_mutex_lock(mutex)
#define dbgcheck__lock_(mutex, file, line) pthread_mutex_lock(mutex)
#define dbgcheck__unlock(mutex) pthread_mutex_unlock(mutex)
#define dbgcheck__unlock_(mutex, file, line) pthread_mutex_unlock(mutex)
#define dbgcheck__named_lock(mutex_var) pthread_mutex_lock(&mutex_var)
#define dbgcheck__named_lock_(mutex, m_name, file, line) \
    pthread_mutex_lock(mutex)
#define dbgcheck__dont_lock_x_when_y_locked(mutex_var1, mutex_var2)
#define dbgcheck__dont_lock_x_when_y_locked_(m1_name, m2_name)

#define dbgcheck__malloc(size, set_name) malloc(size)
#define dbgcheck__calloc(size, set_name) calloc(1, size)
#define dbgcheck__strdup(src, set_name) strdup(src)

#define dbgcheck__free(ptr, set_name) free(ptr)
#define dbgcheck__ptr(root_ptr, set_name)
#define dbgcheck__ptr_size(root_ptr, set_name, size)
#define dbgcheck__inner_ptr(inner_ptr, root_ptr, set_name)
#define dbgcheck__inner_ptr_size(inner_ptr, root_ptr, set_name, size)
#define dbgcheck__fail_if(cond, fmt, ...)
#define dbgcheck__fail_if_(cond, file, line, fmt, ...)
#define dbgcheck__warn_if(cond, fmt, ...)

// This always returns 0 when dbgcheck_on is not defined.
long    dbgcheck__bytes_used_by_set_name(const char *set_name);

#endif
