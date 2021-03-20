# FINJ
Why do we have this project?
We want to test the software in the background when it is being used by users,
but we don't expect that the users perceive our testing.
For such a purpose, we implemented FINJ, a run-time test framework.
It has three sub-projects:
- finj-core
- finj-clang
- finj-hook


## finj-core
This sub-project mainly provides an interface `checkpoint()`.

`checkpoint()` is just like the `fork()` syscall -- it will fork a new
process (which we called **snapshot process**) when the caller invokes it.
However, `checkpoint()` has an important extra feature beyond the `fork()`:
the subsequent execution on the snapshot process will not generate any
side effects such as reading or writing file systems. For example, if the
snapshot process tries to write some bytes to a file, it may be killed before
such a write or the bytes will be redirected to some isolated environment.
Based on this feature, we can execute some test logic on the snapshot process
without worrying that the test logic will be perceived by users, which is the
purpose of the FINJ project.

How do we implement the feature we mentioned above?
We made it by forking a **monitor process** along with the snapshot process.
The monitor process will use `ptrace()` to watch the snapshot process and
mock the syscalls from the snapshot process. For example, if a snapshot process
writes a file, the monitor will swallow this write syscall and return a fake value
to make the snapshot process believes the syscall succeeded. If the monitor cannot
suppress any side effects of the syscalls from the snapshot process, e.g., the
snapshot wants to read a file but the monitor cannot mock the content of the file,
it will kill the snapshot process.

You can use `make` to build a dynamic library `libfinjcore.so` that contains
`checkpoint()`.

## finj-clang
Now that we have `checkpoint()`, we can test the software in the background
without generating any side effects that can be perceiveed by users.
The testing technique we choose is the **library-level fault injection**.

We intend to do this by calling `checkpoint()` at the entrance of a library
call to fork a snapshot process and returning errors immediately on it.

The implementation problem is how we insert `checkpoint()` to the entrances of
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

You can use `make` to compile `finj-clang` along with some necessary runtimes.
Then use `make install` to install them. After that, you can use `finj-clang`
as a normal compiler to compile any project you want to test itself during
the runtime.

You can also find a configuration file at `/home/.finjconfig` and a log file
at `/tmp/finj.log` (after a first run).

## finj-hook (deprecated)
This project is a deprecated way to insert `checkpoint()` to the entrances of
library calls. You'd better use finj-clang as mentioned above.

If you want to use `finj-hook`, first, use `make` to build a dynamic library
`libfinjhook.so`. Then, include the `finj/hook.h` in your C codes and link
`libfinjhook.so` on compiling.
