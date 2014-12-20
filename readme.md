# dbgcheck

*Check your C before you wreck your C.*

The dbgcheck library addresses the most difficult aspects of
debugging C code: memory and threading issues.

In particular, dbgcheck helps to avoid and isolate the following types of problems:
* buffer overflows,
* use of freed or unallocated memory,
* double-freeing memory,
* double-lock-acquiring,
* double-lock-freeing, and
* unsafe concurrency.

These are achieved by wrapping your calls to memory management and threading functions with
`dbgcheck`-defined macros. You do *not* need to wrap these throughout the code - isolated uses
are fine. You also do not need to use any specific `malloc` implementation.

The best part about `dbgcheck` is that you can turn it off at compile-time so that it adds
absolutely zero overhead to the runtime efficiency of your application in production.
The idea here is to test thoroughly with `dbgcheck` turned on, using it to isolate and eliminate
bugs -- then turn it off in production if application speed is critical.

When `dbgcheck` finds an error, it reports the specific file and line where that error occurred.
If used correctly, this will be the exact location in your code where something has first
gone wrong. (I say "if used correctly" because if you only wrap some of your critical calls, and
the error is in an unwrapped call, then `dbgcheck` cannot detect that error.)
In addition most (but currently not all) error detection is synchronous so that breakpoints can
be placed within `dbgcheck.c` to provide a way to either print a stack trace or use an
interactive debugger to gain insight into the error.

## Memory checks

### Theory

At a very high level, only two things can go wrong with memory. Either you try to access an address
that isn't allocated, or you run out of it.

If we treat all memory operations as byte-level reads or writes, then we can recategorize all
possible errors like so:

* computing an invalid address,
* copying a too-large block to a given destination, or
* using too much memory.

*(Some low-level programs may also run into problems with aliasing, where a copy operation has been
performed in an incorrect order causing a loss of data. From our byte-operation perspective, an
aliasing error is not considered a low-level memory management problem.)*

This categorization makes sense in terms of `malloc` and `free` since every allocated block is an
island, and the only valid pointers within that block must be always be ultimately derived from
the starting address of that block. Hence the only way to arrive at an invalid address is to either
not use a valid starting address, or to add an invalid offset to a valid starting address.

### Practice

Internally, `dbgcheck` adds additional bookkeeping to track memory references.
When you allocate a block with `dbgcheck`, slightly more memory than you requested is actually
allocated, and a block prefix is used to track the size of the block. `malloc` independently tracks
block sizes, but `dbgcheck` is specifically designed to assume nothing beyond the formally
specified behavior of `malloc`.

Whenever you want to access memory using a pointer, you have the option of asking `dbgcheck` to
verify the validity of your pointer. This works by classifying pointers as either
*root pointers* or *inner pointers*. A root pointer points to the beginning of an allocated block;
in other words, it is the return value from `dbgcheck__malloc` or any of the other `dbgcheck`-based
allocating functions (the others wrap `strdup` and `calloc`). An inner pointer may point anywhere
within an allocated block or to the byte directly after the end of the allocated block.
This last case is useful for performing conditional checks of the form `my_ptr < block_end_ptr`,
and is a legal C pointer value.

Suppose you want to copy a string into an allocated block. To check the validity of the copy,
`dbgcheck` asks you to provide the root pointer of the destination, the number of bytes about to
be copied, and the destination pointer if it's not the same as the root pointer. Since `dbgcheck`
can determine the full valid range of the destination block, this is sufficient to know exactly
whether or not the copy operation is valid.

In a sense, this kind of check is analogous to the difference between `strcpy` and `strncpy`.
The difference is that `dbgcheck` can help you to verify that the value of *n* you provide
matches the available memory at the destination.

When a block is deallocated `dbgcheck` does something a little crazy, which is that it does *not*
free the memory - it simply marks it so that it will know the memory has been freed. For those of
you freaking out about your memory disappearing, please understand that this element of `dbgcheck`
is designed for small use cases to help you isolate errors. In production, undefine the
`dbgcheck_on` macro before including `dbgcheck.h`, which turns off this feature.

By leaving blocks allocated, `dbgcheck` is extremely likely to detect double-frees and
access-after-free errors.

This methodology gives us a way to
check for any of the three major categories of memory errors. The technical details of
using `dbgcheck` to achieve this are covered in the API section below.

## Threading checks

### Theory

There are two major bugs that can occur in multithreaded code:

* Two sections of code intended to never run concurrently
  may run concurrently, or
* a thread may become stuck waiting forever on a lock.

The first category of bug is difficult to check automatically, since the decision of which sections of code are not meant to
run concurrently is nontrivial. The `dbgcheck` library does not
attempt to solve this problem, but instead helps to clarify and
verify the concurrency rules set up by the programmer;
`dbgcheck` can also provide some checks against low-level lock
usage errors. These checks are described in the next
section.

Another relevant idea is *lock nesting*: we say that lock
*A* nests outside lock *B* when some code locks *B* while *A*
is already locked. A deadlock between *A* and *B* can occur if
they nest outside each other.
More generally, we can create a directed *nesting graph*
between locks where node *A* is connected to *B*
(*A* → *B*) when *A* nests outside *B*. Then a deadlock between
these locks can only occur if this graph contains a cycle.

The `dbgcheck` library does not currently know about lock
nesting behavior or graphs beyond trivial cases. However,
it is good design to think and communicate clearly about
lock nesting behavior.

### Practice

The `dbgcheck` library offers two types of thread-safety checks.
1. Some checks communicate and verify that a concurrency design is upheld.
2. Other checks wrap mutex lock and unlock calls to check for certain error cases.

### Communicating and verifying concurrency design

Any given block of C code is either thread-safe, expected to run in a single thread, or
expected to be run in a way that avoids concurrency with certain other code.

In this document, we'll discuss such code blocks as if they were always functions; however
`dbgcheck` supports these checks at different points within functions as well.

In the thread-safe case, there is no incorrect thread scenario, so `dbgcheck` has no
verification function. However, it is recommended to clarify which functions are
meant to be thread-safe with a comment. There are different degrees of thread-safety as well,
such as being reentrant (safe to call recursively) or being safe to call concurrently if the
inputs are different (such as a function that manipulates an input struct). A function that uses
changing static variables fails both of these thread-safety conditions. It is recommended to
use a comment to clearly label which code blocks are thread-safe, and to use a more specific
nomenclature than simply "thread-safe."

Functions that expect to only be called from the same thread may use the `dbgcheck__same_thread`
function. This will notice as soon as the function is run from a second thread, concurrently or not.

Some functions may expect to be run from different threads, but never concurrently. To verify this,
you may use the `dbgcheck__start_sync_block` and `dbgcheck__end_sync_block` pair. These accept a
string literal as input, which is the name of the `sync_block`.
They pay attention to whether or not that block is ever entered twice, which
indicates an unexpected concurrency. This same mechanism can be used to verify when multiple
functions are all meant to avoid concurrency with each other.

Finally, some functions may expect their caller to have already locked a mutex or used some other
concurrency control to enter a `sync_block`. This expectation can be communicated and verified with
the `dbgcheck__in_sync_block` function, which notices if it is called outside of a
started-but-not-yet-ended `sync_block` of the given name.

The `dbgcheck` library also wraps the calls `pthread_mutex_lock` and `pthread_mutex_unlock` with
`dbgcheck__lock` and `dbgcheck__unlock` to notice the following error cases:

* a thread trying to lock a mutex it currently has locked, or
* a thread trying to unlock a mutex it does not have locked.

If a mutex is being used to avoid concurrency around a group of `sync_block` code blocks, then it's
recommended to wrap the mutex controls around the `sync_block` checks, like so:

    dbgcheck__lock(&lock);
    dbgcheck__start_sync_block("my sync block");

    // your concurrency-avoiding code here

    dbgcheck__end_sync_block("my sync block");
    dbgcheck__unlock(&lock);

Using these functions in any other order would result in a `sync_block` call occurring when the lock was not
held, which could result in a concurrency violation.

### Clarity of code design

Note that these calls are designed for both verification *and communication*. Even when `dbgcheck` is
turned off, these lines clarify the expected thread behavior of your program, which is a good thing.

## API Reference

The "functions" below are all macros. They are defined this way so that they can use the
compiler-defined `__FILE__` and `__LINE__` macros to know which code location the function is
being called from. This is used to print out code location information if an error condition is
noticed.

When an error condition is noticed by `dbgcheck` - and when `dbgcheck` is turned on -
your app will exit immediately with some indication as to why. In almost all cases, your app
will exit with error code 1 and will print out the file name, line number, and an explanation of
what expectation was not met. In the exceptional case that you performed a pointer check where you
sent in a non-root pointer as a root pointer, your app will exit due to either a `SIGSEGV` or a
`SIGBUS`. In these cases, the recommended method of debugging is to attach a debugger before the
signal is sent and examine the stack when the signal occurs.

In the descriptions below the words *notice* and *expect* always indicate conditions which, if
something goes wrong, will cause `dbgcheck` to exit your application with a message (or produce
  SIGSEGV/SIGBUS in the exceptional case just mentioned).

In case some readers are wondering why it's a good thing for a library to crash your app,
keep in mind that your app will only cause this to happen if it already contains a serious bug that
leads to undefined or frozen behavior. The usefulness of `dbgcheck` is in isolating and defending
against these errors with much greater transparency.

### Memory functions

#### ❑ `void *dbgcheck__malloc(size_t size, const char *set_name)`

This wraps a call to `malloc`. The additional `set_name` parameter is used to
verify that the `dbgcheck__free` call that deallocates this block uses the same name.
This is a way to both verify that your `free`s match your `malloc`s, and to communicate about,
and ease searching for, all memory management calls related to the same type of object.

#### ❑ `void *dbgcheck__calloc(size_t size, const char *set_name)`

This is similar to `dbgcheck__malloc`, except that it wraps `calloc` instead of `malloc`;
thus the allocated memory block is set to all zero.

#### ❑ `char *dbgcheck__strdup(const char *src, const char *set_name)`

This wraps a call to `strdup`. The additional `set_name` parameter enables communication and
verification about which type of object is being allocated. See the `dbgcheck__malloc` description
for more details about `set_name`.

#### ❑ `void  dbgcheck__free(void *ptr, const char *set_name)`

This frees a memory block allocated by `dbgcheck__{malloc,calloc,strdup}`. The `set_name` parameter
is expected to match the `set_name` given to the allocating function.

#### ❑ `void  dbgcheck__ptr(void *root_ptr, const char *set_name)`

This function checks that the given `root_ptr` points to the beginning of a memory block allocated
with one of `dbgcheck`'s allocation functions.
It also checks that the memory block was allocated with the given `set_name`.

#### ❑ `void  dbgcheck__ptr_size(void *ptr, const char *set_name, size_t size)`

This performs the same checks as `dbgcheck__ptr`, and also checks that the given `ptr` - which
is expected to be a root pointer - has at least `size` room allocated in it. This is a great
check to perform before a function that may perform buffer overflows if used incorrectly; for
example:

    size_t buf_size = a_size;
    dbgcheck__ptr_size(dst_ptr, "dst str", buf_size);
    strncpy(dst_ptr, src_ptr, buf_size);

#### ❑ `void  dbgcheck__inner_ptr(void *inner_ptr, void *root_ptr, const char *set_name)`

This performs the same checks as `dbgcheck__ptr`, and also checks that the given `inner_ptr` points
to some point within, or at the very end of, the memory block pointed to by `root_ptr`.
Recall that C allows pointers to point to exactly one byte beyond an allocated memory block.
To illustrate this idea:

```
char *root_ptr = malloc(a_size);
char *inner_ptr = root_ptr + a_size;  // inner_ptr is legal
inner_ptr++;                          // ruh-roh; no longer legal
```

#### ❑ `void  dbgcheck__inner_ptr_size(void *inner_ptr, void *root_ptr, const char *set_name, size_t size)`

This performs the same checks as `dbgcheck__inner_ptr`. It also checks that there are at least
`size` allocated bytes available in the memory block starting at `inner_ptr`. Similar to
`dbgcheck__ptr_size`, this helps to avoid buffer overflows. For example:

```
size_t buf_tail_size = a_size;
dbgcheck__inner_ptr_size(inner_p, root_p, "dst str", buf_tail_size);
strncpy(inner_p, src_p, buf_tail_size);
```

Here are tips to help remember the order of parameters in these last four functions:
* The `set_name` is always immediately after the root pointer.
* If there's an inner pointer, it's always first.
* If there's a size, it's always last.
* The order and existence of `inner_ptr`, `root_ptr`, and `size` always follow the
  order and existence of the words `inner`, `ptr`, and `size` in the function name.

### Thread functions

TODO

### General condition checks

TODO
