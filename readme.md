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

## Memory philosophy

TODO

## Threading philosophy

TODO

## API

TODO
