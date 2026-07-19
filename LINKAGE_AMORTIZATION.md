# Linkage Amortization in HarnessReducer

This document explains the linkage-amortization feature from the beginning. It
is written for readers who have not studied compilers, linkers, shared
libraries, or fuzzing infrastructure.

The most important idea is:

> During harness reduction, the harness changes thousands of times, but the
> target library and crashing input usually do not. We prepare those unchanged
> parts once and reuse them.

The implementation supports:

- shared libraries such as `libaom.so`;
- static libraries such as `libaom.a`;
- multiple shared libraries;
- multiple static libraries; and
- a mixture of shared and static libraries.

## 1. The situation HarnessReducer is trying to improve

A fuzz harness is a small function that passes generated input to a much larger
target library. A simplified harness looks like this:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    aom_decode(data, size);  // Function implemented inside libaom.
    return 0;
}
```

HarnessReducer tries to remove unnecessary harness code while preserving the
same crash. TreeReduce may propose thousands of candidates:

```text
original harness
      |
      +-- candidate 1: remove a variable
      +-- candidate 2: remove an if statement
      +-- candidate 3: shorten an expression
      +-- candidate 4: remove a function call
      `-- ...
```

Every candidate must be compiled and executed to answer one question:

```text
Does this smaller candidate still produce the expected crash?
```

Without linkage amortization, candidate testing repeatedly performs work like
this:

```text
candidate 1 -> compile -> link with libaom -> executable 1 -> run
candidate 2 -> compile -> link with libaom -> executable 2 -> run
candidate 3 -> compile -> link with libaom -> executable 3 -> run
                            ^
                            |
                 the same large library is
                 processed again and again
```

The harness source changes, so compiling it again is necessary. The target
library does not change, so repeatedly combining it with every candidate is the
work we want to avoid.

The word **amortization** means paying a cost once and spreading that cost over
many operations. Here, the expensive target-library setup is paid once and
reused across many candidate tests.

## 2. A beginner's guide to compilation and linking

It helps to understand the normal build process before looking at the
optimization.

### 2.1 Source files and headers

A source file such as `harness.cpp` contains C++ code. It may include header
files:

```cpp
#include <aom/aom_decoder.h>
```

A header usually provides declarations, types, macros, and templates. It tells
the compiler that a function exists and how it should be called. The actual
machine code for the function normally lives in a library.

### 2.2 Compilation produces an object file

The compiler translates source code into machine-code pieces:

```bash
clang++ -c harness.cpp -o harness.o
```

The `-c` flag means “compile only; do not create a complete program yet.” The
result, `harness.o`, is called an **object file**.

Suppose `harness.cpp` calls `aom_decode()`. The compiler can generate the call,
but it does not know where the final `aom_decode()` machine code will be located.
The object therefore contains an unresolved reference, often called an
**undefined symbol**:

```text
harness.o
  defines:    LLVMFuzzerTestOneInput
  needs:      aom_decode
```

A symbol is essentially a name for a function or global variable.

### 2.3 Linking connects symbol users to symbol definitions

The linker combines object files and libraries. It finds a definition of
`aom_decode` and connects the call in `harness.o` to that definition:

```text
harness.o                       libaom
  needs aom_decode  --------->  defines aom_decode
        |
        +---------- linker ----------> complete output
```

A normal command might be:

```bash
clang++ harness.o -L/path/to/lib -laom -o harness
```

Here:

- `-L/path/to/lib` adds a directory in which the linker should search;
- `-laom` asks for a library named `libaom.so` or `libaom.a`;
- `-o harness` names the output executable.

### 2.4 Execution is a separate stage

After linking, Linux starts the executable. If it uses shared libraries, the
Linux dynamic loader locates and maps them into the process.

This distinction is important:

```text
-L/path             helps find a library while building
LD_LIBRARY_PATH     helps find a shared library while running
```

HarnessReducer derives runtime search directories from `--link-flags` and adds
them to `LD_LIBRARY_PATH`. This is why a separate runtime rpath is normally not
needed when the binary is executed through HarnessReducer.

## 3. Static and shared libraries are fundamentally different

Both library types contain reusable target code, but they are packaged and used
in different ways.

### 3.1 A static library: `.a`

A static library is an archive of object files:

```text
libaom.a
  +-- decoder.o
  +-- parser.o
  +-- frame_buffer.o
  `-- many other object files
```

It is not a runnable file and cannot be loaded with `dlopen()`. During a normal
link, the linker copies required object files from the archive into the output
executable.

The linker is normally selective. If the current program needs only a symbol
from `decoder.o`, the linker may copy `decoder.o` but leave the other archive
members unused.

### 3.2 A shared library: `.so`

A shared library is already a loadable ELF image:

```text
libaom.so
  +-- machine code
  +-- exported symbols
  +-- relocation information
  `-- dependency information such as libc or libpthread
```

Linux can map it into a running process. A program can load it automatically at
startup or explicitly at runtime:

```cpp
void *handle = dlopen("/path/libaom.so", RTLD_NOW | RTLD_GLOBAL);
```

The process uses the mapped library code; the code does not need to be copied
into every executable.

### 3.3 Why one method cannot be used for both

```text
`.so`: already a loadable runtime image -> use dlopen()
`.a`:  archive of object files           -> must be linked into something
```

Calling `dlopen("libaom.a", ...)` does not work because a static archive does
not have the runtime structure expected by the dynamic loader. Conversely,
copying a complete `.so` into the runner is unnecessary because the `.so` is
already designed to be loaded.

The feature therefore uses two preparation paths that lead to the same final
goal: make target symbols visible to candidate plugins.

## 4. The high-level solution

HarnessReducer builds one persistent process called `harness_runner`.

```text
Prepared once                              Repeated for every candidate
-----------------------------------        ------------------------------
harness_runner                             compile changed harness body
ASan and UBSan runtimes                    create small candidate.so
crashing input bytes                       ask runner to execute candidate.so
shared target mappings
statically linked target code
optional PCH file
```

The complete flow is:

```text
                          ONE-TIME SETUP
             +------------------------------------+
             | build persistent harness_runner    |
             |                                    |
             | static `.a` code is linked inside  |
             | shared `.so` files are loaded      |
             | crash input is read into memory    |
             +-----------------+------------------+
                               |
                        keep runner alive
                               |
       +-----------------------+-----------------------+
       |                       |                       |
       v                       v                       v
 candidate 1              candidate 2              candidate 3
 compile small plugin     compile small plugin     compile small plugin
       |                       |                       |
       +----------- send plugin path to runner --------+
                               |
                               v
                      fork isolated executor
                      load candidate plugin
                      call LLVMFuzzerTestOneInput
                      return crash status and log
```

This optimization does not eliminate all candidate linking. Every candidate is
still turned into a small `.so` plugin. It removes the larger repeated operation
of building a complete executable with all target libraries for every
candidate.

## 5. How `--link-flags` is classified

Before building the runner, HarnessReducer must decide which inputs are shared
libraries, which are static archives, and which are ordinary dependencies.

### 5.1 Explicit paths

An explicit filename gives a direct answer:

```bash
--link-flags="/path/libone.so /path/libtwo.a"
```

- a name ending in `.so` or a versioned form such as `.so.1` is treated as a
  shared library;
- a name ending in `.a` is treated as a static library.

The extension is not trusted by itself. HarnessReducer checks the file header:

- a shared library must be a real ELF file;
- a static library must have a normal or thin `ar` archive header.

This validation matters because some development files named `libsomething.so`
are actually text linker scripts. The linker understands those scripts, but
`dlopen()` cannot load them as ELF code.

### 5.2 `-L` and `-l`

The common linker form is:

```bash
--link-flags="-L/path/to/lib -laom"
```

It means:

```text
-L/path/to/lib   search this directory
-laom            search for a library whose base name is aom
```

In its normal dynamic-preference mode, HarnessReducer checks for:

```text
/path/to/lib/libaom.so
/path/to/lib/libaom.a       (fallback if the `.so` is absent)
```

An exact library filename can also be requested:

```bash
-l:libaom.a
-l:libaom.so
```

### 5.3 `-Wl,-Bstatic` and `-Wl,-Bdynamic`

The selection mode can be changed from left to right:

```bash
--link-flags="-L/path/to/lib \
  -Wl,-Bstatic -lone -ltwo \
  -Wl,-Bdynamic -lthree -lpthread"
```

HarnessReducer interprets it as:

```text
-Wl,-Bstatic
    -lone       -> choose libone.a
    -ltwo       -> choose libtwo.a

-Wl,-Bdynamic
    -lthree     -> prefer libthree.so
    -lpthread   -> prefer the dynamic system dependency
```

`-Wl` contains a lowercase letter **l**, not the digit **1**. It tells the
compiler driver to pass the following comma-separated option to the linker.

The mode switches affect following `-l...` arguments. An explicit `.a` or `.so`
path already identifies its own type.

### 5.4 Target libraries versus ordinary dependencies

Libraries resolved inside explicit `-L` directories are treated as target
inputs. A system flag such as `-lpthread` may not resolve inside those
directories. In that case it remains an ordinary dependency for the one-time
runner link when static archives require it.

For a correctly built shared target, normal dependencies are also recorded in
the target's ELF `DT_NEEDED` entries. Loading `libaom.so` causes the Linux loader
to load those dependencies recursively:

```text
dlopen(libaom.so)
      |
      +-- load libc if needed
      +-- load libpthread if needed
      `-- load libm if needed
```

Explicitly calling `dlopen()` again for every system dependency normally gives
no speed benefit. The dynamic loader already keeps one mapping of each loaded
library in the persistent process.

If the harness directly calls a nonstandard shared library that is not recorded
as a dependency of another target, identify it explicitly with a full `.so`
path or with an explicit `-L` directory.

## 6. One-time setup shared by both library types

Before discussing their differences, these steps are common.

### 6.1 Build the persistent runner

For a shared-only configuration, the simplified command is:

```bash
clang++ -std=c++17 \
  -fsanitize=address,undefined \
  -O1 -gline-tables-only -fno-omit-frame-pointer \
  harness_runner.cpp \
  -ldl \
  -o harness_runner
```

What is being done:

- compile the runner's C++ control logic;
- include ASan and UBSan runtimes;
- include the dynamic-loading API through `-ldl`;
- create one executable that stays alive during reduction.

Why it is done once:

- the runner code does not change between candidates;
- sanitizer initialization does not need to be repeated by a newly built
  executable for every candidate;
- the runner becomes the stable environment into which changing candidate
  plugins are loaded.

### 6.2 Read the crash input once

At startup, the runner reads the crashing input file into a byte vector.

Why:

- every candidate should receive exactly the same bytes;
- the file does not need to be reopened and reread for every candidate;
- the bytes are inherited by forked children using copy-on-write memory.

### 6.3 Open a Unix-domain socket

The runner listens on a local Unix socket. The candidate tester sends the
absolute path of each new candidate plugin and receives its status and output.

Why:

- TreeReduce and the persistent runner are separate processes;
- they need a small, reliable request/response channel;
- using a path avoids transferring plugin machine code through the socket.

## 7. Shared-library path: what happens and why

Consider:

```bash
--link-flags="/path/libaom.so"
```

### 7.1 Validate the `.so`

What is done:

- confirm that the path exists;
- confirm that its name looks like `.so` or `.so.<version>`;
- confirm that the file starts with the ELF magic bytes.

Why:

The runner will give the file to `dlopen()`. A missing file or text linker
script cannot be loaded. Reporting the problem before reduction gives a much
clearer error.

### 7.2 Start the runner without copying the `.so` into it

What is done:

The normal shared-only runner build does not copy all libaom machine code into
the runner executable. The `.so` path is passed to the runner at startup.

The runner is still linked once with the dynamic libraries and dependency flags
from `--link-flags` inside this linker region:

```bash
-Wl,--no-as-needed  target-or-dependency-dynamic-flags  -Wl,--as-needed
```

Why:

A shared object is already a loadable image. Copying it into the runner would
remove the main benefit of using a shared library and could duplicate code.

The `--no-as-needed` part handles a common real-world problem. Some target
shared libraries use functions from helper libraries but do not record those
helper libraries in their own `DT_NEEDED` entries.

Example:

```text
libpcap.so
  needs symbol: nl_socket_alloc
  but readelf -d libpcap.so does not list libnl-3.so as NEEDED
```

If the runner later does only:

```cpp
dlopen("libpcap.so", RTLD_NOW | RTLD_GLOBAL);
```

the loader may fail immediately:

```text
undefined symbol: nl_socket_alloc
```

By linking the runner once with:

```bash
-Wl,--no-as-needed -L/build/lib -lpcap -lnl-genl-3 -lnl-3 -ldbus-1 -Wl,--as-needed
```

we ask the linker to keep those helper dynamic libraries in the runner's own
runtime dependency list even if `harness_runner.cpp` does not directly call
them. Then they are already available when the runner calls `dlopen()` for the
target.

### 7.3 Load with `RTLD_NOW`

What is done:

```cpp
dlopen(target_path, RTLD_NOW | RTLD_GLOBAL);
```

`RTLD_NOW` asks the loader to resolve required symbols immediately.

Why:

If libaom is missing a dependency or incompatible with the process, the runner
should fail during startup. Without immediate resolution, the error might appear
only after many reduction attempts when a particular function is first called.

When several target `.so` files are passed, HarnessReducer first tries to load
them in the order inferred from `--link-flags`. If that fails, it closes the
partially loaded handles and tries the reverse order once.

Why:

Normal linker command order sometimes expresses dependency direction:

```bash
-ltarget -lhelper
```

but direct `dlopen()` can need the opposite order if `libtarget.so` has an
unrecorded reference to `libhelper.so`:

```text
original order: dlopen(libtarget.so) -> may fail: missing helper symbol
reverse order:  dlopen(libhelper.so)
                dlopen(libtarget.so) -> helper symbol is already visible
```

The reverse retry is only a backup. If both orders fail, the tool stops with an
error and suggests running without `--amortize-link`, because the dependency set
cannot be prepared safely by the persistent runner.

### 7.4 Load with `RTLD_GLOBAL`

What is done:

`RTLD_GLOBAL` adds libaom's exported symbols to the process-wide dynamic lookup
scope.

Why:

The candidate plugin is linked without libaom. It may contain an unresolved
reference to `aom_decode`. When the plugin is later loaded, the dynamic loader
must be able to find `aom_decode` in the already-loaded target.

```text
candidate.so
  needs aom_decode
          |
          +-- global dynamic symbol lookup
                         |
                         `--> libaom.so defines aom_decode
```

If the target were loaded with `RTLD_LOCAL`, its symbols would normally be
private to that load group. The later candidate load could fail with an
“undefined symbol” error.

### 7.5 Reuse the mapping

What is done:

The `.so` remains mapped in the persistent parent. Forked children inherit that
mapping.

Why:

Linux uses copy-on-write after `fork()`. Read-only target code pages can be
shared rather than loaded again for every candidate process.

## 8. Static-library path: what happens and why

Consider:

```bash
--link-flags="/path/libaom.a"
```

The static path needs more linker work because an archive cannot be loaded by
`dlopen()`.

### 8.1 Validate the `.a`

What is done:

- confirm that the path exists;
- confirm that it ends in `.a`;
- confirm that it has an `ar` archive header.

Why:

The one-time runner link expects an archive of object files. Passing arbitrary
data with an `.a` name would otherwise produce a confusing linker error.

### 8.2 Link the archive into the runner once

A simplified command is:

```bash
clang++ ... harness_runner.cpp \
  -no-pie \
  -Wl,--export-dynamic \
  -Wl,--whole-archive libtarget1.a libtarget2.a -Wl,--no-whole-archive \
  -lpthread -lm -ldl \
  -o harness_runner
```

What is done:

All target archive code needed by future candidate plugins is placed in the
persistent runner. This link happens once, before TreeReduce starts testing
candidates.

Why:

A `.a` has no runtime loader representation. Some executable or shared object
must contain its object code. Putting it in the persistent runner makes the
code available to every forked candidate executor without linking it into every
candidate plugin.

### 8.3 Why `--whole-archive` is required

This is the most important static-library detail.

Normal archive behavior is lazy:

```text
linker sees libtarget.a
      |
      +-- is a currently unresolved symbol provided by member X?
             |
             +-- yes -> extract member X
             `-- no  -> leave member X in the archive
```

At runner-build time, `harness_runner.cpp` does not call `aom_decode()`. The
future candidate plugin will call it, but that plugin does not exist yet.

Without `--whole-archive`, the linker sees no current reference from the runner
to most target functions:

```text
harness_runner.cpp          libaom.a
  does not call aom_decode   contains aom_decode
          |
          `--> linker thinks the archive member is unused
               and does not copy it into harness_runner
```

Later, `candidate.so` needs `aom_decode`, but the runner does not contain it. The
plugin load fails.

`--whole-archive` changes the rule:

```text
-Wl,--whole-archive libaom.a
        |
        `--> include every archive member, even if the runner does not
             currently reference its symbols
```

This ensures that functions needed by any future candidate are present.

### 8.4 When static symbols are hidden

There is one important exception to the static-runner path.

Some static archives are built with hidden or protected symbol visibility. For
example, a symbol table may contain:

```text
bpf_validate    GLOBAL HIDDEN
```

What this means:

- a normal executable link can still use `bpf_validate`;
- `harness_runner` can contain the code after linking the archive;
- but `--export-dynamic` cannot publish that hidden symbol for a future
  `dlopen(candidate.so)` lookup.

So this fails:

```text
harness_runner contains bpf_validate
        |
        `-- bpf_validate is hidden

candidate.so needs bpf_validate
dynamic loader cannot see the hidden runner symbol
-> dlopen candidate failed: undefined symbol: bpf_validate
```

What HarnessReducer does now:

```text
first attempt for each candidate
        |
        +-- link candidate.so without target libraries
        |
        +-- ask harness_runner to dlopen(candidate.so)
        |
        +-- dlopen succeeds
        |      `-- keep the fast path
        |
        `-- dlopen fails with "undefined symbol"
               |
               `-- relink the same candidate object with the original
                   --link-flags, then retry
```

Why:

The fallback is only used after a concrete loader failure. If an archive has
hidden symbols that the current candidate never calls, the fast path still runs.
If the current candidate does call a hidden static API such as `bpf_validate`,
the fallback candidate plugin contains the needed static-library code itself,
so `bpf_validate` is resolved inside `candidate.so` instead of through the
runner.

Tradeoff:

This fallback gives up the static-library speedup only for candidates that
actually need hidden static symbols. Candidates that do not need those symbols
continue using the fast runner-export path. If the archive was not compiled as
position-independent code, fallback linking into `candidate.so` may still fail;
in that case the reliable choices are a default-visible shared target build or
running without `--amortize-link`.

### 8.5 Why `--no-whole-archive` is required afterward

What is done:

```bash
-Wl,--whole-archive libaom.a -Wl,--no-whole-archive -lpthread -lm
```

Why:

`--whole-archive` remains active for following archives until it is disabled.
If it accidentally applies to system libraries, the linker may copy enormous
amounts of unnecessary code, produce duplicate definitions, or fail the link.

The feature therefore surrounds only the selected target archives:

```text
whole-archive ON  -> target `.a` files
whole-archive OFF -> normal dependencies
```

### 8.6 Why `--export-dynamic` is required

Placing `aom_decode` inside the runner is not sufficient by itself.

An executable has a normal symbol table for link/debug information and a
dynamic symbol table used by the runtime loader. By default, not every function
inside an executable is published to the dynamic symbol table.

Without `--export-dynamic`:

```text
harness_runner contains aom_decode
candidate.so needs aom_decode
dynamic loader cannot see the runner's private symbol
-> plugin load fails
```

With `--export-dynamic`:

```text
harness_runner contains aom_decode
        |
        +-- publish aom_decode in the dynamic symbol table
        |
candidate.so can resolve aom_decode from the runner
```

What is done:

`-Wl,--export-dynamic` tells the linker to publish executable symbols so that a
later `dlopen()` operation can use them.

Why:

Candidate plugins are loaded dynamically and need to resolve their target calls
against statically linked code inside the main executable.

### 8.7 Why `-no-pie` is used

What is done:

The runner is built as a traditional non-PIE executable when static targets are
present.

Why:

Many existing static archives were compiled as ordinary object code rather than
position-independent code. A position-independent executable can reject some
relocations from such archives. `-no-pie` makes it more likely that ordinary
non-PIC archive objects can be linked into the runner.

This does not remove the need for `-fPIC` on candidate plugins. Plugins are
shared objects and may be mapped at different addresses, so their code must
remain position independent.

### 8.8 Multiple static archives

Multiple archives are put inside the same controlled whole-archive region:

```bash
-Wl,--whole-archive \
  libtarget.a libhelper.a libcodec.a \
-Wl,--no-whole-archive
```

Why:

All members are included once, and references between the archives can be
resolved during the one-time runner link. The candidate loop then reuses the
combined result.

The cost is that the runner can be larger than a normal selectively linked
executable. This is an intentional tradeoff: a larger one-time link is accepted
to eliminate thousands of repeated target links.

## 9. Dynamic and static paths compared directly

| Question | Shared library (`.so`) | Static library (`.a`) |
|---|---|---|
| What is the input? | A loadable ELF image. | An archive of object files. |
| Can `dlopen()` load it? | Yes. | No. |
| Where does target code live? | In a separately mapped `.so`. | Usually inside `harness_runner`; a candidate that needs hidden static symbols is retried with those symbols in `candidate.so`. |
| How is it prepared? | `dlopen(..., RTLD_NOW | RTLD_GLOBAL)`. | One-time runner link with `--whole-archive`; candidate-side fallback is only used after an actual unresolved-symbol load failure. |
| How are symbols exposed? | `RTLD_GLOBAL` makes `.so` exports globally visible. | `--export-dynamic` publishes runner symbols, but it cannot publish hidden/protected symbols. |
| Why not normal archive linking? | Not applicable. | The runner has no direct target references, so normal lazy extraction would omit needed members. |
| What is inherited after `fork()`? | Shared-library mappings. | Runner text containing archive code; fallback candidate code is loaded only when needed. |
| Is the target linked into each candidate? | No. | No normally; yes only for candidates that fail the fast `dlopen()` path with an unresolved symbol. |

The two paths differ during one-time preparation, then meet at the same symbol
lookup point:

```text
                         global symbol scope
                        /                   \
          loaded shared-library symbols    exported runner symbols
                    (`.so`)                       (`.a`)
                        \                   /
                         candidate.so lookup
```

## 10. What happens when static and dynamic libraries are mixed

Example:

```bash
--link-flags="-L/path/to/lib \
  -Wl,-Bstatic -ltarget -lhelper \
  -Wl,-Bdynamic -lcodec -lpthread"
```

The steps are:

1. Resolve `libtarget.a` and `libhelper.a` as static targets.
2. Resolve `libcodec.so` as a shared target.
3. Link the static archives into `harness_runner` with
   `--whole-archive`.
4. Export their symbols with `--export-dynamic`.
5. Make selected shared targets available during the one-time runner link when
   they are needed to satisfy references from static code.
6. Start the runner.
7. Load `libcodec.so` with `RTLD_NOW | RTLD_GLOBAL`.
8. Load each candidate plugin. Its unresolved target calls may now resolve from
   either the runner or the shared library.
9. If loading a candidate fails with `undefined symbol`, relink that candidate
   plugin with the original `--link-flags` and retry it once.

The result is:

```text
harness_runner process
  |
  +-- target code copied from libtarget.a
  +-- helper code copied from libhelper.a
  +-- globally loaded libcodec.so
  +-- normal runtime dependencies
  `-- one temporary candidate.so at a time in an executor child
```

This also supports dependencies in either direction:

- static target code can call functions supplied by a selected shared library;
- a shared target loaded later can resolve appropriate global symbols exported
  by the runner.

Avoid supplying conflicting definitions of the same symbol in several target
libraries. Dynamic symbol lookup follows ELF resolution rules, and duplicate
definitions can cause a one-time link error or make the selected definition
depend on ordering.

## 11. The repeated candidate path

After target preparation, shared and static configurations use the same
candidate loop.

### 11.1 Optional PCH preparation

Headers may be large and expensive to parse. With `--pch`, HarnessReducer moves
the harness's `#include` directives into `harness_prefix.h` and compiles them
once:

```text
original harness.cpp
        |
        +-- include lines --> harness_prefix.h --> harness_prefix.pch
        |
        `-- changing code --> harness.harness_body.cpp
```

What PCH saves:

- repeated preprocessing and parsing of unchanged headers.

What PCH does not save:

- target-library linking;
- candidate code generation;
- candidate execution.

The PCH is consumed by Clang. It is not loaded into `harness_runner` and the
runner does not maintain a Clang AST.

### 11.2 Compile the candidate as position-independent code

A simplified PCH-mode command is:

```bash
clang++ \
  -include-pch harness_prefix.pch \
  -fsanitize=address,undefined \
  -O0 -gline-tables-only -Werror=uninitialized \
  -fPIC -c \
  candidate.harness_body.cpp \
  -o candidate.o
```

What is done:

- compile only the changing harness body;
- instrument it with ASan and UBSan;
- generate position-independent machine code;
- keep enough line information for useful stack traces.

Why `-fPIC`:

The object will become a shared plugin. Linux may map the plugin at different
virtual addresses, so its machine code must not assume one fixed address.

What would happen without it:

The plugin link may fail with relocation errors, or the resulting shared object
may require unsafe text relocations.

### 11.3 Link the small candidate plugin

```bash
clang++ -shared \
  -fsanitize=address,undefined \
  candidate.o \
  -o candidate.so
```

What is deliberately absent:

```text
no libaom.so
no libaom.a
no full target link
```

The candidate may retain unresolved target symbols. Linux resolves those
symbols when the executor loads `candidate.so` against the already-prepared
global process scope.

If this load fails with `undefined symbol`, the tester does not immediately
return a compile failure. It relinks the same `candidate.o` once with the
original `--link-flags`, then asks the runner to load the new `candidate.so`.
This fallback is only used for that candidate. If the hidden or otherwise
unexported symbol disappears in a later reduced candidate, the later candidate
returns to the lightweight link shown above.

Why `-shared`:

The output must be loadable by `dlopen()`, not independently executable.

### 11.4 Keep the standard fuzz entry point

The plugin exports:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // current candidate harness body
}
```

`extern "C"` prevents C++ name mangling, so the runner can look up one stable
symbol name with `dlsym()`.

The implementation does not rewrite this function to a custom entry-point name.

### 11.5 Send the plugin path to the runner

```text
candidate tester                         persistent runner
      |                                         |
      |--- absolute path to candidate.so ------>|
      |                                         |
      |<-- status + output length + output -----|
```

The protocol sends an absolute path because TreeReduce may invoke testers from
different working directories.

### 11.6 Fork before loading and running the candidate

Candidate code is supposed to reproduce a crash. Running it directly inside the
persistent parent would destroy the state we want to reuse.

The implementation therefore uses:

```text
persistent runner
      |
      `-- fork request monitor
                |
                `-- fork candidate executor
                          |
                          +-- redirect stdout/stderr to a pipe
                          +-- dlopen(candidate.so, RTLD_NOW | RTLD_LOCAL)
                          +-- dlsym("LLVMFuzzerTestOneInput")
                          +-- call function with cached crash bytes
                          `-- exit or crash
```

Why two short-lived levels:

- the executor may crash or hang;
- the monitor captures its output and waits for it;
- the monitor enforces the 300-second timeout;
- the persistent parent remains available for the next request.

Why load candidates with `RTLD_LOCAL`:

Target symbols must be global because later candidates need them. Candidate
symbols should not be global because one candidate must not affect symbol
resolution for another candidate.

### 11.7 Extra crash check for dynamic target libraries

The reducer already checks two things for every candidate:

```text
1. Does the crash pattern still appear?
2. Does the first stack trace have the same number of frames?
```

For static libraries, HarnessReducer still uses those checks. Static target code
is copied into the executable or runner, so the exact executable offsets may move
when the harness changes. When static target libraries are detected, the tool
prints:

```text
[WARN] Static target libraries were detected. Cannot fully guarantee final crash preservation.
```

For dynamic target libraries, HarnessReducer can check one more stable fact.
The target `.so` is already built and does not change during reduction, so an
offset inside that `.so` should stay the same if the crash stays the same.

Example first stack trace:

```text
#0 0x7d1f099eff25  (/path/build/lib/libaom.so+0x201cf25)
#1 0x0000005567d0  (/path/harness+0x5567d0)
#2 0x00000044d5af  (/path/harness+0x44d5af)
```

HarnessReducer records this from the initial fast reference run
(`symbolize=0`), because candidate checks during reduction use the same fast
execution style:

```text
dynamic crash-site library: /path/build/lib/libaom.so
dynamic crash-site offset:  0x201cf25
```

Then a candidate is interesting only if all three checks pass:

```text
same crash pattern
same first-trace depth
same first target-library .so offset
```

The offset check is intentionally applied to `symbolize=0` executions. A
`symbolize=1` stack trace often replaces `(/path/libtarget.so+0xOFFSET)` with a
function name and source line, so the raw shared-library offset may no longer be
visible in that output. Symbolized validation still checks stack shape/source
patterns; the dynamic offset check belongs to the fast unsymbolized path.
During repeated candidate checks, the library comparison uses only stack-trace
strings, path text, and library basenames; it does not resolve symlinks or query
the filesystem.

This helps distinguish two crashes that both say, for example,
`SUMMARY: AddressSanitizer: ABRT` and have the same number of frames, but stop
inside different parts of the target library.

Important details:

- Only the first stack trace is used. If the output later contains another
  trace such as “allocated by thread T0 here,” that later trace is ignored for
  this offset check.
- The code looks for stack frames shaped like `(.../libtarget.so+0x1234)`.
  This is common in sanitizer and libFuzzer outputs, but the logic is not tied
  to ASan specifically.
- If `--link-flags` contains a clear shared-library path or `-L/path -ltarget`,
  that information is used as the target-library hint.
- If there is no `-L` directory, HarnessReducer can still use the first crash
  output to discover which `.so` actually appears in the first stack trace.
- Runtime libraries such as `libc.so`, `libasan.so`, `libstdc++.so`,
  `libpthread.so`, `libm.so`, and the dynamic loader are ignored when using
  this fallback.

### 11.8 Return the result to TreeReduce

The monitor returns the exit status and captured sanitizer output. The tester
checks whether the expected crash pattern, required stack behavior, and any
recorded dynamic-library crash-site offset were preserved. Exit code `77` is
used as TreeReduce's “interesting candidate” code.

Before reduction begins, the original harness is run through this same plugin
path. This calibrates the expected stack depth for the runner/plugin process
layout rather than comparing it with a differently linked standalone program.
If a dynamic target offset was recorded earlier, the original harness must also
preserve that offset in the runner/plugin path.

## 12. Why the runner does not explicitly load every system library

Consider:

```bash
--link-flags="-L/build/lib -laom -lpthread -lm"
```

It may seem that explicitly calling `dlopen()` for libpthread and libm would
save additional time. Usually it would not.

### What already happens

A well-built `libaom.so` records the shared libraries it needs. When the runner
loads libaom, the Linux loader loads those dependencies recursively and retains
them in the persistent process.

For dependency flags that appear in `--link-flags`, HarnessReducer also links
the persistent runner once with `--no-as-needed`. This can keep helper dynamic
libraries in the runner's own `DT_NEEDED` list. That is different from manually
calling `dlopen()` for every `-lfoo`: the normal linker and dynamic loader still
choose the correct runtime objects.

### Why `-lpthread` is not always a loadable filename

`-lpthread` is a linker request, not necessarily a runtime path. Depending on
the system:

- the real runtime file may be `libpthread.so.0`;
- the development file `libpthread.so` may be a linker script;
- pthread functionality may already be integrated into libc.

Blindly converting every `-lfoo` into `dlopen("libfoo.so")` can therefore load
the wrong name or a non-loadable file.

### Why static system archives should not be forced in

Applying `--whole-archive` to all system static libraries could:

- make the runner unnecessarily large;
- introduce duplicate libc/runtime definitions;
- interfere with ASan initialization;
- greatly increase the one-time link cost; or
- fail because the system does not provide a static form of every dependency.

The optimization focuses on large, unchanged target libraries. Normal runtime
dependencies are still loaded once through the standard linker/loader
mechanisms, and dynamic helper dependencies from `--link-flags` are retained by
the one-time runner link when possible.

## 13. Why the sanitizer flags differ from normal fuzz executables

A normal standalone candidate uses:

```text
-fsanitize=address,fuzzer,undefined
```

The `fuzzer` part supplies the libFuzzer driver that repeatedly invokes
`LLVMFuzzerTestOneInput` and usually provides `main()`.

An amortized candidate is not a standalone fuzz executable. `harness_runner`
loads the plugin and calls `LLVMFuzzerTestOneInput` itself. Therefore the runner
and plugins use:

```text
-fsanitize=address,undefined
```

Why omit `fuzzer`:

- the runner already provides the execution control flow;
- the plugin does not need another driver or `main()`;
- linking a standalone libFuzzer driver into every plugin would conflict with
  the plugin model.

The target `.so` and `.a` files must be compatible with the same sanitizer
environment. Mixing incompatible sanitizer runtimes can change crashes or fail
during loading.

## 14. Compiler and linker flag reference

### Candidate compilation

| Flag | What it does | Why this feature uses it |
|---|---|---|
| `clang++` | Runs the Clang C++ compiler driver. | Handles C++ compilation and invokes the linker when needed. |
| `-Qunused-arguments` | Suppresses warnings for driver arguments unused in one stage. | Some option groups are shared between related commands. |
| `-I/path` | Adds a header search directory. | Finds target and HarnessReducer headers. |
| `-DFDP_MIN_MODE_REPLAY` | Defines a preprocessor macro. | Enables deterministic replay of recorded `FuzzedDataProvider` operations. |
| `-fsanitize=address,undefined` | Adds ASan and UBSan instrumentation. | Detects memory errors and undefined behavior in candidate execution. |
| `-O0` | Disables optimization. | Keeps candidate compilation fast and behavior/source locations easier to compare. |
| `-gline-tables-only` | Emits source line tables without full debug data. | Supports useful stack locations with lower debug-data cost. |
| `-Werror=uninitialized` | Makes uninitialized-variable warnings fatal. | Rejects candidates that introduce an obvious invalid uninitialized use. |
| `-fPIC` | Generates position-independent code. | Required for code that becomes a loadable candidate `.so`. |
| `-c` | Compiles without linking. | Produces the intermediate candidate object. |
| `-include-pch file.pch` | Reuses a precompiled header. | Avoids reparsing unchanged includes for each candidate. |
| `-o path` | Names the output. | Selects the object, plugin, or executable path. |

### Plugin and runner linking

| Flag | What it does | Why this feature uses it |
|---|---|---|
| `-shared` | Produces a shared object rather than an executable. | Makes `candidate.so` loadable with `dlopen()`. |
| `-ldl` | Links the dynamic-loading API. | Provides `dlopen()` and `dlsym()` to the runner. |
| `-O1` | Applies light optimization. | Used for stable runner code that is compiled only once. |
| `-fno-omit-frame-pointer` | Retains frame pointers. | Improves sanitizer stack unwinding in runner code. |
| `-Wl,--whole-archive` | Forces all members from following archives into the output. | Keeps static target functions that only future plugins will reference. |
| `-Wl,--no-whole-archive` | Returns to normal selective archive behavior. | Prevents whole-archive behavior from affecting system dependencies. |
| `-Wl,--export-dynamic` | Publishes executable symbols to the dynamic loader. | Lets candidate plugins resolve calls against static target code in the runner. |
| `-Wl,--no-as-needed` | Keeps following dynamic libraries as runtime dependencies even if the runner code does not directly call them. | Lets the persistent runner retain helper DSOs such as libnl when a target `.so` has unresolved helper symbols. |
| `-Wl,--as-needed` | Restores normal behavior after the protected dynamic dependency region. | Prevents the retention rule from unintentionally affecting later linker inputs. |
| `-no-pie` | Builds a non-position-independent executable. | Improves compatibility with static target objects not compiled as PIC. |

## 15. PCH and linkage amortization save different work

These optimizations are complementary:

```text
PCH                    saves repeated parsing of unchanged headers
linkage amortization   saves repeated target-library linking/setup
```

| Mode | Reparse headers each time? | Relink target each time? |
|---|---:|---:|
| `--split` | Yes | Yes |
| `--pch` | No | Yes |
| `--amortize-link` with split mode | Yes | No |
| `--pch --amortize-link` | No | No |

“No” does not mean zero work. Candidate code is still compiled, a small plugin
is still linked, and the candidate is still executed.

## 16. Command examples

### Shared target

```bash
harnessreducer harness.cpp \
  --compile-flags="-I/path/to/target/include" \
  --link-flags="/path/to/libtarget.so" \
  --crash-input crash-input \
  --amortize-link \
  -o reduced.cpp
```

### Multiple shared targets

```bash
--link-flags="-L/path/to/lib -ltarget -lcodec -lhelper -lpthread"
```

### Static target

```bash
--link-flags="/path/to/libtarget.a -lpthread -lm"
```

### Multiple static targets

```bash
--link-flags="-L/path/to/lib \
  -Wl,-Bstatic -ltarget -lcodec -lhelper \
  -Wl,-Bdynamic -lpthread -lm"
```

### Mixed targets

```bash
--link-flags="-L/path/to/lib \
  -Wl,-Bstatic -ltarget_static \
  -Wl,-Bdynamic -ltarget_shared -lpthread"
```

### libaom benchmark with PCH

```bash
harnessreducer harness.cpp \
  --compile-flags="-I/path/to/HarnessMinimizer/include -I$(pwd)/build/sanitizer/include" \
  --link-flags="-L$(pwd)/build/sanitizer/lib -laom" \
  --work-dir ./statistics-pch-link \
  --crash-input crash-input \
  --pch \
  --amortize-link \
  --stable \
  --statistics \
  -o reduced.cpp
```

The benchmark notes currently contain one PCH run at about `321076 ms` and one
PCH-plus-amortized-link run at about `186049 ms`, approximately a 42% reduction
for those recorded runs. This is an example, not a general guarantee. Results
depend on target size, candidate size, disk cache, machine load, and candidate
count.

## 17. What changed from the original proposal

The original idea mentioned an LLVM ORC JIT and a custom replacement function.
The implemented version deliberately uses simpler operating-system mechanisms:

| Original proposal | Current implementation |
|---|---|
| Rename the entry point to a custom function. | Keep `LLVMFuzzerTestOneInput`. |
| Keep a PCH or AST context inside the runner. | Build a PCH once, but Clang consumes it outside the runner. |
| Compile candidates with LLVM ORC JIT/JITLink. | Compile a small `.so` with `clang++`. |
| Execute candidates directly from in-memory JIT output. | Load temporary plugins with `dlopen()` and find the entry point with `dlsym()`. |
| Show one child per candidate. | Use a request monitor and a separate executor for output capture and timeout isolation. |

ORC JIT remains a possible future optimization. It is not part of the current
feature.

## 18. Current limitations and failure cases

- Linux/ELF only.
- At least one target `.so` or `.a` must be identifiable.
- Standalone `.o` and `.lo` inputs are rejected; place static objects in an
  archive.
- A `.so` linker script is rejected because `dlopen()` needs a real ELF file.
- Target code must be compatible with the runner's ASan/UBSan environment.
- Static archives with duplicate definitions may fail the one-time
  `--whole-archive` link.
- Static archives with hidden/protected target symbols cannot expose those
  symbols from the runner. If a candidate actually needs one, HarnessReducer
  retries that candidate by linking it with the original `--link-flags`, which
  is slower and requires the archive objects to be usable in a shared object.
- Mixed libraries with conflicting symbol definitions can produce
  order-dependent symbol resolution.
- If dynamic target libraries still cannot be loaded after dependency retention
  and the reverse-order retry, HarnessReducer fails early and suggests rerunning
  without `--amortize-link`.
- `--amortize-link` works with split or PCH mode, not direct/single-step mode.
- Candidate `.o` and `.so` files are still written to disk; this is not an
  in-memory JIT.
- The optimization applies to the main Phase 3 candidate loop. Some one-off
  validation stages still use normal compilation.

## 19. Short explanation for a presentation

```text
Problem:
  TreeReduce creates thousands of harness candidates.
  The harness changes, but the target library does not.
  Rebuilding a full target-linked executable each time wastes work.

Shared target solution:
  Load the `.so` once with RTLD_GLOBAL.
  Retain dynamic helper libraries in the runner with --no-as-needed.
  If loading multiple target .so files fails, retry the opposite order once.
  Future candidate plugins find target symbols in that loaded library.

Static target solution:
  A `.a` cannot be loaded.
  Link all members into the runner once with --whole-archive.
  Export runner symbols with --export-dynamic.
  If one candidate still fails to load because it needs a hidden static symbol,
  relink only that candidate with the original --link-flags and retry it.

Candidate loop:
  Compile only the changing harness as a small candidate.so.
  Fork an isolated executor.
  Load candidate.so and call LLVMFuzzerTestOneInput.
  A crash kills only the executor, not the persistent runner.

Result:
  PCH reuses unchanged header parsing.
  Linkage amortization reuses unchanged target setup.
```

The core design is: **keep the large, unchanged execution environment alive and
replace only the small harness plugin that TreeReduce is modifying.**
