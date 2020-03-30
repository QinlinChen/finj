# finj
A run-time self-test framework. It has two sub-projects:
- finj-core
- finj-hook

## finj-core
This project mainly provides a interface `checkpoint()` to fork a snapshot
which will keep running as long as possible until it cannot suppress any
side effects to happen. It is just like the `fork()` syscall without any
side effects.

You can use `make` to build a dynamic library `libfinjcore.so`.

## finj-hook
This project provides hooks to insert `checkpoint()` on entering library
calls to fork a snapshot and return errors immediately on the snapshot,
which is called library fault injection.

If you want to use `finj-hook` to test your C codes, first, use `make` to
build a dynamic library `libfinjhook.so`. Then, include the `finj/hook.h`
in your C codes and link `libfinjhook.so` on compiling.
