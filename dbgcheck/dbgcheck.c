// dbgcheck.c
//
// https://github.com/tylerneylon/dbgcheck
//

// TODO
//   * Make more checks synchronous. They only need to be asynchronous if they
//     write to a prefix or access a dbgcheck global.
//   * Add unit tests! This is on its way to being its own library.

#include "dbgcheck.h"

#ifdef dbgcheck_on

#include "cstructs/cstructs.h"
#include "thready/thready.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// This is used for cross-platform Visual-Studio-friendly printing.
#ifdef _WIN32
#define vsnprintf(s, n, fmt, args) vsnprintf_s(s, n, _TRUNCATE, fmt, args)
#define snprintf(s, n, fmt, ...) _snprintf_s(s, n, _TRUNCATE, fmt, __VA_ARGS__)
#define pathsep '\\'
#else
#define OutputDebugString(s) printf("%s", s)
#define pathsep '/'
#endif

#ifndef true
#define true  1
#define false 0
#endif

#pragma warning (disable : 4018)  // Allow signed/unsigned comparison.


// Internal types and globals.

enum {
  action_same_thread,
  action_check_ptr_size,
  action_check_inner_ptr_size,
  action_check_inner_ptr,
  action_check_ptr,
  action_malloc,
  action_free,
  action_did_lock,
  action_will_lock,
  action_unlock
};

typedef struct {
  int              action;
  void *           root_ptr;
  void *           inner_ptr;
  size_t           size;
  const char *     name;      // Expected to live forever; e.g. be a literal.
  char *           loc;       // When non-NULL, this is owned by this struct.
  pthread_t        thread;
  pthread_mutex_t *mutex;
} Action;

// These types are chosen to ensure that, if `Prefix *prefix` is well-aligned
// in the heap, then so is `prefix + 1`; that is, sizeof(Prefix) is a nice
// power of two.
typedef struct {
  size_t       user_size;
  char *       freed_by;  // This is NULL until the chunk is freed.
  const char * set_name;
  void *       unused;
} Prefix;

static int is_initialized = false;

static pthread_mutex_t thready_id_lock = PTHREAD_MUTEX_INITIALIZER;
static Map thready_id_of_loc;   // Used for and only for same_thread checks.

// Lock info types and data.

typedef struct {
  char *       locking_loc;
  pthread_t    locking_thread;
  const char * name;  // This may be NULL.
} LockInfo;

static pthread_mutex_t lock_info_lock;  // kinda meta

// This maps `<weak> pthread_mutex_t *` -> `<strong> LockInfo *`.
static Map lock_info_of_mutex;

// Variables for the mutex directed graph.
static Map             mutex_graph;  // Used as a set of string keys.
static pthread_once_t  mutex_graph_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mutex_graph_lock;

// Variables for sync blocks.
static pthread_once_t sync_blocks_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t sync_blocks_lock;
static Map sync_blocks;  // Maps block name -> block start loc (owned strings).

// We hold a string for every location that calls dbgcheck__free.
// This map acts as a hash set to efficiently keep only one copy of each string.
static Map freed_from_locs;
static pthread_mutex_t freed_from_lock;
static pthread_once_t  freed_from_init_once = PTHREAD_ONCE_INIT;

static Map bytes_per_set_name;  // Maps set_name -> num_bytes.
static pthread_mutex_t bytes_per_name_lock;
static pthread_once_t  bytes_per_name_init_once = PTHREAD_ONCE_INIT;


// Internal functions.

// Define dbg__printf on all platforms.

static int dbg__vprintf(const char *fmt, va_list args) {
  char buffer[2048];
  int chars_written = vsnprintf(buffer, 2048, fmt, args);
  OutputDebugString(buffer);

  return chars_written;
}

static int dbg__printf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int chars_written = dbg__vprintf(fmt, args);
  va_end(args);

  return chars_written;
}

#define failure(...)                 \
  dbg__printf("dbgcheck failure: "); \
  dbg__printf(__VA_ARGS__);          \
  exit(1);

static void freer(void *vp, void *context) {
  free(vp);
}

static int str_hash(void *str_void_ptr) {
  char *str = (char *)str_void_ptr;
  int h = *str;
  while (*str) {
    h *= 84207;
    h += *str++;
  }
  return h;
}

static int str_eq(void *str_void_ptr1, void *str_void_ptr2) {
  return !strcmp(str_void_ptr1, str_void_ptr2);
}

static const char *basename(const char *path) {
  char *last_slash = strrchr(path, pathsep);
  return last_slash ? last_slash + 1 : path;
}

// This may run on any thread, but has protections in place to only
// be called once ever.
static void init_mutex_graph() {
  pthread_mutex_init(&mutex_graph_lock, NULL);
  mutex_graph = map__new(str_hash, str_eq);
  // This map is expected to only grow; no keys are ever released.
}

// This may run on any thread.
static void init_sync_blocks() {
  pthread_mutex_init(&sync_blocks_lock, NULL);
  sync_blocks = map__new(str_hash, str_eq);
  // We don't set a key releaser as we expect the names to live forever,
  // e.g. to be string literals.
  sync_blocks->value_releaser = freer;
}

// This may run on any thread.
static void init_bytes_per_name() {
  pthread_mutex_init(&bytes_per_name_lock, NULL);
  bytes_per_set_name = map__new(str_hash, str_eq);
}

// This may run on any thread.
static void init_freed_from_locs() {
  pthread_mutex_init(&freed_from_lock, NULL);
  freed_from_locs = map__new(str_hash, str_eq);
}

// This may run on any thread.
// sign is expected to be +1 or -1, depending on if the given root_ptr was just
// allocated or freed.
static void update_bytes_for_set_name(void *root_ptr, const char *set_name, int sign) {
  // We define this as most of the uses of set_name below treat it directly as a void *.
  void *set_name_vp = (void *)set_name;

  pthread_once(&bytes_per_name_init_once, init_bytes_per_name);
  pthread_mutex_lock(&bytes_per_name_lock);
  map__key_value *pair = map__find(bytes_per_set_name, set_name_vp);
  if (pair == NULL) {
    pair = map__set(bytes_per_set_name, set_name_vp, 0L);
  }
  long num_bytes = (long)pair->value;
  Prefix *prefix = (Prefix *)root_ptr - 1;
  num_bytes += sign * prefix->user_size;
  map__set(bytes_per_set_name, set_name_vp, (void *)num_bytes);
  pthread_mutex_unlock(&bytes_per_name_lock);
}

// This may run outside of dbgcheck_thread.
static void fail_if_already_freed(void *root_ptr, char *loc) {
  Prefix *prefix = (Prefix *)root_ptr - 1;
  char *freed_by = prefix->freed_by;
  if (freed_by) {
    
    // In bad cases, the root_ptr may not point to a valid dbgcheck-allocated
    // and our freed_by pointer may cause a seg or bus fault when accessed.
    // Because of that, we print a general error statement first before trying
    // to print out the freed_by string, which should be a code location string.
    
    dbg__printf("dbgcheck failure: freed pointer checked at %s.\n", loc);
    dbg__printf("This block was freed at %s.\n", freed_by);
    exit(1);
  }
}

// These are for pointer values used directly as hash keys in a map.
static int hash(void *v) {
  return (int)(intptr_t)v;
}

static int eq(void *v1, void *v2) {
  return v1 == v2;
}

static void free_lock_info(void *lock_info_vp, void *context) {
  LockInfo *lock_info = (LockInfo *)lock_info_vp;
  free(lock_info->locking_loc);
  free(lock_info);
}

// This function expects lock_info_lock to be locked before it's called.
static void ensure_graph_edge_exists(const char *to, char *loc) {
  pthread_mutex_lock(&mutex_graph_lock);
  map__for(pair, lock_info_of_mutex) {
    const char *from = ((LockInfo *)pair->value)->name;
    if (from == NULL) {
      failure("consistently use/don't use named_lock interface: %s vs %s",
              ((LockInfo *)pair->value)->locking_loc, loc);
    }
    char *edge_name = (char *)malloc(1048);
    snprintf(edge_name, 1048, "%s -> %s", basename(from), basename(to));
    if (map__find(mutex_graph, edge_name)) {
      free(edge_name);
    } else {
      map__set(mutex_graph, edge_name, NULL);
    }
  }
  
  pthread_mutex_unlock(&mutex_graph_lock);
}

// Only runs on dbgcheck_thread.
static void handle_msg(void *msg, thready__Id from) {
  Action *action = (Action *)msg;

  // We don't need locks as this function only runs in one thread.
  if (!is_initialized) {
    
    pthread_mutex_lock(&thready_id_lock);
    if (thready_id_of_loc == NULL) {
      // This may already be set up if dbgcheck_sync_same_thread is defined.
      thready_id_of_loc  = map__new(str_hash, str_eq);
    }
    pthread_mutex_unlock(&thready_id_lock);
    
    freed_from_locs    = map__new(str_hash, str_eq);

    pthread_once(&bytes_per_name_init_once, init_bytes_per_name);
    
    pthread_mutex_init(&lock_info_lock, NULL);  // NULL --> default attributes
    lock_info_of_mutex = map__new(hash, eq);
    lock_info_of_mutex->value_releaser = free_lock_info;
    
    pthread_once(&mutex_graph_init_once, init_mutex_graph);
    
    is_initialized = true;
  }

  // This switch takes ownership of action->loc.
  switch (action->action) {
    case action_same_thread:
      {
        // Note that this will only run if dbgcheck_sync_same_thread is not
        // defined; so if this code executes, thready_id_of_loc is only
        // accessed from a single thread. Hence we do not need locks.
        
        map__key_value *pair = map__find(thready_id_of_loc, action->loc);
        if (pair == NULL) {
          map__set(thready_id_of_loc, action->loc, from);
          // The map now owns action->loc.
        } else {
          if (from != (thready__Id)pair->value) {
            failure("same_thread at %s.\n", action->loc);
          }
          free(action->loc);
        }
      }
      break;
      
    case action_will_lock:
      {
        pthread_mutex_lock(&lock_info_lock);
        map__key_value *pair = map__find(lock_info_of_mutex, action->mutex);
        // In correct operation, the lock is held by another thread, or not
        // held at all.
        if (pair && ((LockInfo *)(pair->value))->locking_thread == action->thread) {
          // TODO Check that failures when die_on_failure is off don't leak!
          failure("lock obtained twice by the same thread at %s\n", action->loc);
          // Now we are in a deadlocked state :(
        }
        if (action->name) {
          ensure_graph_edge_exists(action->name, action->loc);
        }
        // action->loc will be sent to and owned by action_did_lock.
        pthread_mutex_unlock(&lock_info_lock);
      }
      break;
      
    case action_did_lock:
      {
        pthread_mutex_lock(&lock_info_lock);
        LockInfo *lock_info = malloc(sizeof(LockInfo));
        lock_info->locking_loc    = action->loc;  // lock_info now owns loc.
        lock_info->locking_thread = action->thread;
        lock_info->name           = action->name;  // Expected to be eternal.
        map__set(lock_info_of_mutex, action->mutex, lock_info);
        pthread_mutex_unlock(&lock_info_lock);
      }
      break;
      
    case action_unlock:
      {
        pthread_mutex_lock(&lock_info_lock);
        map__key_value *pair = map__find(lock_info_of_mutex, action->mutex);
        // In correct operation, the lock is held by the unlocking thread.
        if (!pair || ((LockInfo *)(pair->value))->locking_thread != action->thread) {
          failure("unlock attempted when lock is owned by another thread at %s\n",
                  action->loc);
        }
        map__unset(lock_info_of_mutex, action->mutex);
        pthread_mutex_unlock(&lock_info_lock);
      }
      free(action->loc);
      break;

    default:
      failure("Internal dbgcheck error! Unexpected action value %d!\n", action->action);
  }

  free(action);
}

// This may run outside of dbgcheck_thread.
static void send_action(Action *action) {
  thready__Id dbgcheck_thread = thready__create_once(handle_msg);
  thready__send(action, dbgcheck_thread);
}

// This may run outside of dbgcheck_thread.
static char *new_loc(const char *file, int line) {
  char *loc = (char *)malloc(256);
  snprintf(loc, 256, "%s:%d", file, line);
  return loc;
}

// This is designed to be used like so and only like so:
//     Action *action = new_action {
//       .action   = <my_action>,
//       .root_ptr = <my_ptr> };
#define new_action        \
  malloc(sizeof(Action)); \
  *action = (Action)

// This may run outside of dbgcheck_thread.
static void *post_alloc(Prefix *prefix, size_t size, const char *set_name, char *loc) {
  prefix->user_size = size;
  prefix->freed_by  = NULL;
  // We count on set_name being written before the user's dbgcheck-alloc call
  // completes; if we wrote this asynchronously, then we couldn't later
  // synchronously check that it exists outside the dbgcheck thread.
  prefix->set_name  = set_name;
  
  void *ptr = (char *)prefix + sizeof(Prefix);

  update_bytes_for_set_name(ptr, set_name, 1);  // 1 --> alloc (vs dealloc)
  free(loc);
  
  return ptr;
}

// I consider this safe to run outside of the dbgcheck_thread because it only
// reads the memory, and it is expected for the set name to have been set before
// any memory-oriented call checks it. In other words, it is definitely a user
// error if this check fails, even if it fails while the set name is being set
// concurrently, because that means the user attempted to do something with the
// memory before knowing it was fully allocated.
static char *check_set_name(void *ptr, const char *set_name, const char *file, int line) {
  char *loc = new_loc(file, line);
  if (ptr == NULL) {
    failure("Expected non-NULL pointer at %s.\n Checked set name '%s'.\n",
            loc, set_name);
  }
  Prefix *prefix = (Prefix *)ptr - 1;
  if (strcmp(set_name, prefix->set_name) != 0) {
    failure("ptr set name mismatch at %s.\n"
            "malloc set name '%s'; expected set name '%s'.\n",
            loc, prefix->set_name, set_name);
  }
  return loc;
}

// This may run outside of dbgcheck_thread.
static void print_msg(const char *prefix, const char *file, int line, const char *fmt, va_list args) {
  char *loc = new_loc(file, line);
  dbg__printf("%s: custom condition failed at %s\n", prefix, loc);
  free(loc);
  dbg__vprintf(fmt, args);
}


// Public functions.

void dbgcheck__same_thread_(const char *file, int line) {
  
  char *loc = new_loc(file, line);
  
#ifdef dbgcheck_sync_same_thread
  
  // Synchronous version.
  
  pthread_mutex_lock(&thready_id_lock);
  
  if (thready_id_of_loc == NULL) {
    thready_id_of_loc  = map__new(str_hash, str_eq);
  }
  
  thready__Id my_id = thready__my_id();
  map__key_value *pair = map__find(thready_id_of_loc, loc);
  if (pair == NULL) {
    map__set(thready_id_of_loc, loc, my_id);
    // The map now owns action->loc.
  } else {
    if (my_id != (thready__Id)pair->value) {
      failure("same_thread at %s.\n", loc);
    }
    free(loc);
  }
  
  pthread_mutex_unlock(&thready_id_lock);
  
#else
  
  // Asynchronous version.
  
  // The thread id will be known in `handle_msg` via the `from` parameter.
  Action *action = new_action {
    .action = action_same_thread,
    .loc    = loc
  };
  send_action(action);
  
#endif
}

void dbgcheck__start_sync_block_(const char *name, const char *file, int line) {
  pthread_once(&sync_blocks_init_once, init_sync_blocks);
  char *loc = new_loc(file, line);
  pthread_mutex_lock(&sync_blocks_lock);
  map__key_value *pair = map__find(sync_blocks, (void *)name);
  if (pair) {
    failure("overlapping sync block: %s\n"
            "first started at %s / second started at %s\n",
            name, (char *)pair->value, loc);
  } else {
    map__set(sync_blocks, (void *)name, loc);  // sync_blocks now owns loc.
  }
  pthread_mutex_unlock(&sync_blocks_lock);
}

void dbgcheck__end_sync_block_(const char *name, const char *file, int line) {
  pthread_once(&sync_blocks_init_once, init_sync_blocks);
  char *loc = new_loc(file, line);
  pthread_mutex_lock(&sync_blocks_lock);
  map__key_value *pair = map__find(sync_blocks, (void *)name);
  if (pair) {
    map__unset(sync_blocks, (void *)name);
    free(loc);
  } else {
    failure("end sync block when not in block: %s\n"
            "end called at %s.\n", name, loc);
  }
  pthread_mutex_unlock(&sync_blocks_lock);
}

void dbgcheck__in_sync_block_(const char *name, const char *file, int line) {
  pthread_once(&sync_blocks_init_once, init_sync_blocks);
  char *loc = new_loc(file, line);
  pthread_mutex_lock(&sync_blocks_lock);
  map__key_value *pair = map__find(sync_blocks, (void *)name);
  if (pair == NULL) {
    failure("not in sync block as expected: %s\n"
            "expected to be in block at %s.\n", name, loc);
  }
  pthread_mutex_unlock(&sync_blocks_lock);
}

void dbgcheck__lock_(pthread_mutex_t *mutex, const char *file, int line) {
  char *loc = new_loc(file, line);
  Action *action = new_action {
    .action = action_will_lock,
    .name   = NULL,
    .loc    = loc,
    .thread = pthread_self(),
    .mutex  = mutex
  };
  send_action(action);
  pthread_mutex_lock(mutex);
  action = new_action {
    .action = action_did_lock,
    .loc    = loc,
    .thread = pthread_self(),
    .mutex  = mutex
  };
  send_action(action);
}

void dbgcheck__unlock_(pthread_mutex_t *mutex, const char *file, int line) {
  char *loc = new_loc(file, line);
  Action *action = new_action {
    .action = action_unlock,
    .loc    = loc,
    .thread = pthread_self(),
    .mutex  = mutex
  };
  send_action(action);
  pthread_mutex_unlock(mutex);
}

void  dbgcheck__named_lock_(pthread_mutex_t *mutex, const char *mutex_name, const char *file, int line) {
  // TODO Factor out redundancy with dbgcheck__lock_.
  char *loc = new_loc(file, line);
  Action *action = new_action {
    .action = action_will_lock,
    .name   = mutex_name,
    .loc    = loc,
    .thread = pthread_self(),
    .mutex  = mutex
  };
  send_action(action);
  pthread_mutex_lock(mutex);
  action = new_action {
    .action = action_did_lock,
    .name   = mutex_name,
    .loc    = loc,
    .thread = pthread_self(),
    .mutex  = mutex
  };
  send_action(action);
}

void dbgcheck__ptr_(void *ptr, const char *set_name, const char *file, int line) {
  char *loc = check_set_name(ptr, set_name, file, line);
  fail_if_already_freed(ptr, loc);
  free(loc);
}

void dbgcheck__ptr_size_(void *ptr, const char *set_name, size_t size, const char *file, int line) {
  char *loc = check_set_name(ptr, set_name, file, line);
  fail_if_already_freed(ptr, loc);
  Prefix *prefix = (Prefix *)ptr - 1;
  if (prefix->user_size < size) {
    failure("pointer size too small at %s.\n"
            "pointer block has size %zd; planned usage size is %zd.\n",
            loc, prefix->user_size, size);
  }
  free(loc);
}

void dbgcheck__inner_ptr_(void *inner_ptr, void *root_ptr, const char *set_name, const char *file, int line) {
  char *loc = check_set_name(root_ptr, set_name, file, line);
  fail_if_already_freed(root_ptr, loc);
  Prefix *prefix = (Prefix *)root_ptr - 1;
  char *root_byte = (char *)root_ptr;
  ptrdiff_t byte_delta = (char *)inner_ptr - root_byte;
  if (byte_delta < 0 || byte_delta > prefix->user_size) {
    failure("inner pointer out of range at %s.\n"
            "root chunk appears to be [%p - %p]; inner pointer is at %p.\n",
            loc, root_byte, root_byte + prefix->user_size, inner_ptr);
  }
  free(loc);
}

void dbgcheck__inner_ptr_size_(void *inner_ptr, void *root_ptr, const char *set_name, size_t size, const char *file, int line) {
  char *loc = check_set_name(root_ptr, set_name, file, line);
  Prefix *prefix = (Prefix *)root_ptr - 1;
  char *root_end = (char *)root_ptr + prefix->user_size;
  if (inner_ptr < root_ptr || inner_ptr > (void *)root_end) {
    failure("inner ptr outside of root_ptr range at %s.\n"
            "root_ptr range is [ %p - %p ]; inner_ptr is %p.\n",
            loc, root_ptr, root_end, inner_ptr);
  }
  char *end_used_byte = (char *)inner_ptr + size;
  if (end_used_byte > root_end) {
    failure("inner ptr was expected to have more space at %s.\n"
            "actual bytes available is %zd; expected bytes available is %zd.\n",
            loc, (root_end - (char *)inner_ptr), size);
  }
  free(loc);
}

void *dbgcheck__malloc_(size_t size, const char *set_name, const char *file, int line) {
  Prefix *prefix = (Prefix *)malloc(size + sizeof(Prefix));
  return post_alloc(prefix, size, set_name, new_loc(file, line));
}

void *dbgcheck__calloc_(size_t size, const char *set_name, const char *file, int line) {
  Prefix *prefix = (Prefix *)calloc(1, size + sizeof(Prefix));
  return post_alloc(prefix, size, set_name, new_loc(file, line));
}

char *dbgcheck__strdup_(const char *src, const char *set_name, const char *file, int line) {
  size_t src_size = strlen(src) + 1;  // + 1 is for the final null.
  Prefix *prefix = (Prefix *)malloc(src_size + sizeof(Prefix));
  char *str_start = post_alloc(prefix, src_size, set_name, new_loc(file, line));
  char *dst = str_start;
  while ((*dst++ = *src++));  // Copy the string; this includes the final null.
  return str_start;
}

void dbgcheck__free_(void *ptr, const char *set_name, const char *file, int line) {
  char *loc = check_set_name(ptr, set_name, file, line);

  fail_if_already_freed(ptr, loc);
  update_bytes_for_set_name(ptr, (void *)set_name, -1);  // -1 --> dealloc (vs alloc)

  Prefix *prefix = (Prefix *)ptr - 1;

  pthread_once(&freed_from_init_once, init_freed_from_locs);
  pthread_mutex_lock(&freed_from_lock);
  map__key_value *pair = map__find(freed_from_locs, loc);
  if (pair == NULL) {
    pair = map__set(freed_from_locs, loc, NULL);
    // loc is now owned by freed_from_locs.
  } else {
    free(loc);
  }
  pthread_mutex_unlock(&freed_from_lock);

  prefix->freed_by = pair->key;
}

void dbgcheck__fail_if_(int cond, const char *file, int line, const char *fmt, ...) {
  if (!cond) { return; }
  va_list args;
  va_start(args, fmt);
  print_msg("dbgcheck failure", file, line, fmt, args);
  va_end(args);
  exit(1);
}

void dbgcheck__warn_if_(int cond, const char *file, int line, const char *fmt, ...) {
  if (!cond) { return; }
  va_list args;
  va_start(args, fmt);
  print_msg("dbgcheck warning", file, line, fmt, args);
  va_end(args);
}

long dbgcheck__bytes_used_by_set_name(const char *set_name) {
  pthread_once(&bytes_per_name_init_once, init_bytes_per_name);
  pthread_mutex_lock(&bytes_per_name_lock);
  map__key_value *pair = map__find(bytes_per_set_name, (void *)set_name);
  pthread_mutex_unlock(&bytes_per_name_lock);
  return pair ? (long)pair->value : 0;
}

char *dbgcheck__get_lock_graph_str() {
  
  pthread_mutex_lock(&mutex_graph_lock);
  
  // First pass: determine the size of the string.
  size_t bytes_needed = 0;
  map__for(pair, mutex_graph) {
    // The +4 here is for two spaces + a newline, which may be 2 chars on win.
    bytes_needed += (strlen((char *)pair->key) + 4);
  }
  bytes_needed++;  // Make room for the final NULL.
  
  // Second pass: fill in the string.
  char * full_str   = (char *)malloc(bytes_needed);
  char * tail       = full_str;
  size_t bytes_left = bytes_needed;
  map__for(pair, mutex_graph) {
    int bytes_added = snprintf(tail, bytes_left, "  %s\n", (char *)pair->key);
    tail += bytes_added;
    bytes_left -= bytes_added;
  }
  
  pthread_mutex_unlock(&mutex_graph_lock);
  
  return full_str;
}

#else

long dbgcheck__bytes_used_by_set_name(const char *set_name) {
  return 0;
}

char *dbgcheck__get_lock_graph_str() {
 return "";
}

#endif
