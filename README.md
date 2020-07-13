# FINJ
We want to do some run-time test in the background during software is
being used by users. However, we don't want users to perceive this.
So we implemented FINJ, a run-time test framework.
It has three sub-projects:
- finj-core
- finj-clang
- finj-hook


## finj-core
This project mainly provides an interface `checkpoint()` to fork a snapshot
process when the caller invokes it. It is just like the `fork()` syscall.
However, we implemented an important extra feature: the subsequent execution
flow on the snapshot process will not generate any side effects such as
reading or writing file systems so that we can execute some test logic on
the snapshot process and it will not be perceived by users.

We made it by forking a monitor process along with the snapshot process.
The monitor process will use `ptrace()` to watch the snapshot process and
kill it if the monitor cannot suppress any side effects from the snapshot
process to happen.

You can use `make` to build a dynamic library `libfinjcore.so`.

## finj-clang
Now that we have `checkpoint()`, we want to test software by library fault
injection. We intend to do this by calling `checkpoint()` on entering library
calls to fork a snapshot and return errors immediately on the snapshot process.

The implementation problem is how we insert `checkpoint()` to the entrance of
library calls? This project handles this problem by providing a clang wrapper
`finj-clang` that will replace library functions with their fault-injected
versions such as this on compiling:

        void *finj_malloc(size_t size) {
            if (checkpoint() == SNAPSHOT) {
                errno = ENOMEM
                return NULL;
            }
            return malloc(size);
        }

You can use `make` to compile and `make install` to install the `finj-clang`
and some necessary runtimes. Then you can use `finj-clang` as a common compiler.


## finj-hook (deprecated)
This project is a deprecated way to insert `checkpoint()` to the entrance of
library calls. You'd better use finj-clang as mentioned above.

If you want to use `finj-hook`, first, use `make` to build a dynamic library
`libfinjhook.so`. Then, include the `finj/hook.h` in your C codes and link
`libfinjhook.so` on compiling.
