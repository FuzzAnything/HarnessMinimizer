# Linkage Amortization in HarnessReducer

This document explains why linkage amortization was added, how the current
implementation works, and what the compiler flags mean. It assumes no previous
knowledge of compilers.

## 1. The problem in one sentence

Harness reduction tests many slightly different versions of the same harness,
but the large target library and the crashing input stay the same.

Without linkage amortization, HarnessReducer repeatedly links the unchanged
target library into a new executable. Linkage amortization prepares the target
once—by loading a shared library or linking a static archive into the persistent
runner—and turns every changing harness candidate into a small plugin.

> **Amortization** means paying a setup cost once and reusing the result many
> times.

## 2. A small compilation primer

Suppose we have a C++ source file called `harness.cpp`. Producing something the
computer can run normally has three conceptual stages:

```text
harness.cpp                 harness.o                  harness executable
(human-readable C++)        (machine code pieces)      (complete program)
      |                            |                            |
      | preprocess + compile       | link                       | execute
      v                            v                            v
  [ compiler ]  ------------>  [ object file ]  ----------> [ process ]
                                      +
                                target library
                                      +
                                sanitizer runtime
```

### Compile

The compiler translates one source file into an **object file**, usually ending
in `.o`. The object contains machine code, but it may still refer to functions
defined somewhere else.

For example, the harness may call a function from libaom. At this point the
object file knows the function's name, but not its final address.

### Link

The linker combines object files and libraries. It connects calls in the
harness to definitions in libaom and produces either:

- an executable program; or
- a shared object (`.so`), which another program can load later.

### Execute

Linux starts the executable and its dynamic loader locates any required shared
libraries. This is a different step from linking. A directory passed with `-L`
helps the linker find a library while building; `LD_LIBRARY_PATH` helps Linux
find it while running.

## 3. Why normal harness reduction repeats work

Tree reduction creates many candidate source files:

```text
original harness
      |
      +--> candidate A: remove one statement
      +--> candidate B: remove one branch
      +--> candidate C: remove one variable
      `--> ... possibly thousands more
```

Each candidate must be tested. A candidate is **interesting** only if it still
reproduces the original crash.

In the normal split or PCH path, every test does this:

```text
candidate A -> compile A.o -> link A.o + libaom -> executable A -> run
candidate B -> compile B.o -> link B.o + libaom -> executable B -> run
candidate C -> compile C.o -> link C.o + libaom -> executable C -> run
                                      ^
                                      |
                         the same target is processed again
```

Only the harness candidate changes. The target library, sanitizer runtime, and
crashing input do not. For a large target such as libaom, repeatedly performing
the full executable link is redundant.

PCH mode already reduces repeated **compilation** work by precompiling the
headers. It does not remove the repeated link with the target library.

## 4. The implemented idea

The implementation separates stable parts from changing parts:

```text
Built or loaded once                         Rebuilt for every candidate
-----------------------------------          -----------------------------
persistent runner                            small candidate object (`.o`)
shared target (`libaom.so`) and/or            small candidate plugin (`.so`)
static target (`libaom.a`)
sanitizer runtime
crashing input bytes
optional precompiled header (PCH)
```

The overall data flow is:

```text
                         START ONCE
              +--------------------------------+
              | persistent runner              |
              |                                |
              | load `.so` / contain `.a` code |
              | read crash input               |
              | open a Unix socket             |
              +---------------+----------------+
                              |
                    remains alive during
                     the reduction loop
                              |
           +------------------+------------------+
           |                  |                  |
           v                  v                  v
      candidate A        candidate B        candidate C
      compile +          compile +          compile +
      small `.so`        small `.so`        small `.so`
           |                  |                  |
           +-------- send plugin path ----------+
                              |
                              v
                   fork an isolated process,
                   load plugin, call harness,
                   return status and crash log
```

This does **not** remove all linking. Each candidate object is still linked into
a small plugin. It avoids repeatedly linking the candidate together with the
large target library into a complete executable.

## 5. What happens before the reduction loop

### Step 1: Check and resolve the target libraries

`--amortize-link` requires at least one target shared library or static archive.
All of these forms are accepted:

```bash
--link-flags "/absolute/path/libaom.so"
```

```bash
--link-flags "-L/absolute/path -laom"
```

```bash
--link-flags "/absolute/path/libaom.a"
```

For the second form:

- `-L/absolute/path` says where to search;
- `-laom` means “find `libaom.so`, or fall back to `libaom.a`”.

Multiple libraries are supported. A linker script named like a `.so` is rejected
because `dlopen()` needs a loadable ELF file. Standalone `.o` and `.lo` files are
also rejected; put those objects into a `.a` archive first.

Relative library paths are converted to absolute paths because TreeReduce may
run candidate tests from a different working directory. Library directories are
also placed in `LD_LIBRARY_PATH` during execution, so an additional
`-Wl,-rpath,...` is not required when running through HarnessReducer.

### Step 2: Build the persistent runner

HarnessReducer compiles `harness_runner.cpp` once:

```bash
clang++ -std=c++17 \
  -fsanitize=address,undefined \
  -O1 -gline-tables-only -fno-omit-frame-pointer \
  harness_runner.cpp \
  -ldl \
  -o harness_runner
```

The runner contains the sanitizer runtime and the code needed for dynamic
loading, process isolation, timeouts, and communication.

When static archives are present, their code is added to this one-time command:

```bash
clang++ ... harness_runner.cpp \
  -no-pie -Wl,--export-dynamic \
  -Wl,--whole-archive libtarget1.a libtarget2.a -Wl,--no-whole-archive \
  -ldl -o harness_runner
```

`--whole-archive` is necessary because the runner source does not directly call
target functions. Without it, the linker could discard all archive members as
unused. `--export-dynamic` makes those target functions visible when a candidate
plugin is loaded. `-no-pie` allows ordinary non-PIC static archive code to be
placed in the runner executable; candidate plugins still use `-fPIC`.

### Step 3: Load stable data once

At startup, the runner loads every target shared library:

```cpp
dlopen(target_path, RTLD_NOW | RTLD_GLOBAL);
```

- `RTLD_NOW` resolves required symbols immediately, so missing symbols fail at
  startup rather than much later.
- `RTLD_GLOBAL` makes target symbols visible to candidate plugins. A candidate
  can therefore call libaom functions without being linked directly to libaom.

The runner also reads the crashing input file into memory once. Every candidate
receives the same bytes.

Static target code needs no startup `dlopen()` call because it is already part
of the runner executable.

### Step 4: Optionally build the PCH once

With `--pch`, HarnessReducer moves `#include` lines into a generated prefix
header and compiles that header into `harness_prefix.pch`. The changing body is
compiled against this PCH for every candidate.

```text
original harness.cpp
        |
        +--> include lines --> harness_prefix.h --> harness_prefix.pch (once)
        |
        `--> remaining body --> candidate body (changes repeatedly)
```

The PCH is reused by the compiler. It is **not** stored as an AST inside the
persistent runner.

## 6. Where dynamic and static libraries are handled differently

The candidate loop is the same for both library types. The difference is how
the stable target code is placed into the runner before that loop begins:

| Step | Dynamic library (`.so`) | Static library (`.a`) |
|---|---|---|
| Resolve the input | Confirm that it is a loadable ELF shared object. | Confirm that it is an `ar` archive. |
| Build the runner | Normally does not copy target code into the runner. | Link all archive members into the runner once with `--whole-archive`. |
| Make symbols visible | `dlopen(..., RTLD_GLOBAL)` adds symbols to the global loader scope. | `--export-dynamic` publishes the symbols already inside the runner. |
| Start the runner | Load each `.so` and read the crash input. | Only read the crash input; static code is already present. |
| Load a candidate | The loader resolves candidate calls against the loaded `.so`. | The loader resolves candidate calls against exported runner symbols. |
| Later candidates | Reuse the inherited shared-library mappings after `fork()`. | Reuse the inherited runner code after `fork()`. |

In both cases, each candidate is still compiled into the same small plugin. No
target library is linked into each candidate plugin.

### Selecting static and dynamic libraries

An explicit filename is unambiguous:

```bash
--link-flags "/path/libone.a /path/libtwo.a /path/libthree.so"
```

For `-l` names, the normal default is to prefer `.so` and fall back to `.a`.
GNU linker mode switches can make the choice explicit:

```bash
--link-flags "-L/path/to/lib \
  -Wl,-Bstatic -lone -ltwo \
  -Wl,-Bdynamic -lthree -lpthread"
```

The spelling is `-Wl` with a lowercase letter **l**, meaning “pass the following
option to the linker.” `-W1` with the digit **1** is incorrect.

The selected static archives are linked into the runner once. The selected
shared libraries are loaded once. If a static archive calls a function from one
of the selected shared libraries, that shared library is also present during the
one-time runner link so the dependency can be resolved.

## 7. What happens for every candidate

### Step 1: Compile the candidate into position-independent code

In split mode, the whole candidate source is compiled. In PCH mode, the smaller
include-free body is compiled with `-include-pch`.

A simplified PCH command is:

```bash
clang++ \
  -include-pch harness_prefix.pch \
  -fsanitize=address,undefined \
  -O0 -gline-tables-only -Werror=uninitialized \
  -fPIC -c \
  candidate.harness_body.cpp \
  -o candidate.o
```

The entry point remains the standard fuzz-harness function:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // candidate harness logic
}
```

The current implementation keeps this standard entry-point name unchanged.

### Step 2: Link only the small candidate plugin

The candidate object becomes a shared object:

```bash
clang++ -shared \
  -fsanitize=address,undefined \
  candidate.o \
  -o candidate.so
```

Notice that the target library is absent from this command. When the runner
loads the plugin, its symbols are resolved from loaded shared targets and/or
static target symbols exported by the runner.

### Step 3: Send the plugin path to the runner

The tester connects to the persistent runner through a Unix-domain socket and
sends the absolute path of `candidate.so`.

```text
candidate tester                         persistent runner
      |                                         |
      |--- "/tmp/candidate.so\n" -------------->|
      |                                         |
      |<-- exit status + output size + log -----|
```

A Unix-domain socket is local inter-process communication. It behaves like a
small network connection but stays on the same machine.

### Step 4: Fork before running unsafe code

A candidate is expected to crash, so it must not run directly inside the
persistent parent. The implementation uses two short-lived levels:

```text
persistent runner (keeps serving future candidates)
        |
        `-- fork request monitor
                  |
                  `-- fork candidate executor
                            |
                            +-- dlopen(candidate.so, RTLD_NOW | RTLD_LOCAL)
                            +-- dlsym("LLVMFuzzerTestOneInput")
                            +-- call function with cached crash input
                            `-- crash or exit
```

The monitor captures standard output and standard error, enforces the 300-second
timeout, converts a signal into an exit status, and sends the result back to the
tester. If the executor crashes, the persistent runner survives and accepts the
next candidate.

The executor loads the plugin with `RTLD_LOCAL`, so symbols from one candidate
are not made globally visible to later candidates.

Because `fork()` copies the parent's process state using copy-on-write, the
children inherit the already-loaded target mappings and cached input without
loading them again from scratch.

### Step 5: Decide whether the candidate is interesting

HarnessReducer checks the returned status and crash output. In the reduction
loop, exit code `77` means the expected crash was preserved. A normal run or a
different failure means the proposed source reduction is rejected.

Before reduction starts, the original harness is also run through this same
amortized path. This recalibrates the expected stack depth for the changed
process layout.

## 8. Why each compiler flag is present

### Candidate compilation flags

| Flag | Plain-language meaning | Why it is used here |
|---|---|---|
| `clang++` | Run the Clang C++ compiler driver. | It selects C++ compilation and also knows how to invoke the linker. |
| `-Qunused-arguments` | Do not warn when a driver option is irrelevant to one stage. | The same flag groups are reused across compile and link commands. |
| `-I/path` | Add a directory to the header search path. | Lets `#include` find project and target headers. |
| `-DFDP_MIN_MODE_REPLAY` | Define a preprocessor macro. | Selects deterministic replay behavior for the recorded fuzz-data-provider trace. |
| `-fsanitize=address,undefined` | Add checks for invalid memory access and undefined behavior. | Detects and reports the target crash. |
| `-O0` | Disable optimization. | Keeps compilation fast and stack traces/source behavior easier to compare during reduction. |
| `-gline-tables-only` | Keep source file and line-number debug information, but not full debug data. | Produces useful stack locations with less compile/debug-data cost than full `-g`. |
| `-Werror=uninitialized` | Turn an uninitialized-variable warning into a compile error. | Prevents a reduced candidate with obvious uninitialized use from being accepted as a valid crash-preserving harness. |
| `-fPIC` | Generate position-independent code. | Required because the object will be loaded at an arbitrary address as part of a shared object. |
| `-c` | Compile only; do not link yet. | Produces `candidate.o`. |
| `-include-pch file.pch` | Start compilation with a previously compiled header. | Avoids reparsing unchanged headers for every candidate in PCH mode. |
| `-o path` | Name the output file. | Selects the `.o`, `.so`, or executable path. |

### Plugin and runner link flags

| Flag | Plain-language meaning | Why it is used here |
|---|---|---|
| `-shared` | Produce a loadable `.so` instead of an executable. | Makes each candidate a plugin. |
| `-ldl` | Link the dynamic-loading API library. | Gives the runner `dlopen()` and `dlsym()`. |
| `-fno-omit-frame-pointer` | Keep a regular frame pointer in generated runner code. | Helps sanitizer stack unwinding remain reliable. |
| `-O1` | Apply light optimization. | Used for the stable runner, which is built only once, rather than changing candidate code. |
| `-Wl,--whole-archive` | Force every object in following static archives into the output. | Prevents unreferenced target functions from being discarded. |
| `-Wl,--no-whole-archive` | End the forced archive inclusion region. | Avoids applying `--whole-archive` to normal system dependencies. |
| `-Wl,--export-dynamic` | Put executable symbols in its dynamic symbol table. | Lets candidate plugins find statically linked target functions. |
| `-no-pie` | Build a traditional fixed-address executable. | Allows the runner to contain static archives that were not compiled as PIC. |

### Why amortized plugins omit `-fsanitize=fuzzer`

Normal executable candidates use:

```text
-fsanitize=address,fuzzer,undefined
```

The `fuzzer` part supplies the libFuzzer execution driver for a standalone fuzz
executable. An amortized candidate is not a standalone executable: the runner
looks up and calls `LLVMFuzzerTestOneInput` itself. Therefore candidate plugins
and the runner use only:

```text
-fsanitize=address,undefined
```

The target shared libraries and static archives must be sanitizer-compatible as
well.

## 9. PCH and linkage amortization solve different costs

These options can be used together because they save work at different stages:

```text
                         repeated work reduced by
                         ------------------------
parsing large headers  -> PCH
linking large target   -> linkage amortization
```

The four useful comparisons are:

| Mode | Reparse headers each time? | Relink target each time? |
|---|---:|---:|
| `--split` | Yes | Yes |
| `--pch` | No | Yes |
| `--amortize-link` (split) | Yes | No |
| `--pch --amortize-link` | No | No |

Here “No” means the expensive repeated portion is reused. A small amount of
candidate compilation and plugin linking still occurs.

## 10. libaom example

The current benchmark command uses PCH and linkage amortization together:

```bash
harnessreducer harness.cpp \
  --compile-flags "-I/path/to/HarnessMinimizer/include -I$(pwd)/build/sanitizer/include" \
  --link-flags "-L$(pwd)/build/sanitizer/lib -laom" \
  --work-dir ./statistics-pch-link \
  --crash-input crash-input \
  --pch \
  --amortize-link \
  --stable \
  --statistics \
  -o reduced.cpp
```

The important parts are:

- `--compile-flags` supplies header locations needed while translating source;
- `--link-flags` identifies the loadable target library;
- `--pch` reuses parsed headers;
- `--amortize-link` reuses the loaded target and input;
- `--stable` asks TreeReduce for deterministic reduction behavior;
- `--statistics` records candidate result counts.

The benchmark notes currently show one PCH run at about `321076 ms` and one
PCH-plus-amortized-link run at about `186049 ms`. That is approximately a 42%
reduction for those recorded runs. This is an illustrative result, not a general
guarantee: the speedup depends on target size, candidate size, disk cache,
machine load, and the number and type of candidates tested.

## 11. What changed from the original design proposal

The original proposal described the intended direction. The implementation is
simpler and uses standard Linux shared libraries and static archives:

| Original proposal | Current implementation |
|---|---|
| Normalize the entry point to a custom `RunOne` function | Keep and look up `LLVMFuzzerTestOneInput` |
| Keep “PCH / AST context” inside the runner | Build a PCH once, but the compiler consumes it outside the runner |
| Use LLVM ORC JIT/JITLink | Use `clang++` to create a small `.so`, then use `dlopen()`/`dlsym()` |
| Possibly compile and execute entirely in memory | Write a temporary candidate object and plugin to disk |
| One child shown per candidate | Use a request-monitor child plus an executor child for safe logging and timeout handling |

ORC JIT remains a possible future optimization. It is not part of the current
feature.

## 12. Current limitations

- Linux/ELF only.
- Requires at least one target `.so` or `.a`.
- Standalone object files are rejected; static inputs must be archives.
- The target library must be built in a way compatible with the runner's ASan
  and UBSan environment.
- Static archives are linked with `--whole-archive`; duplicate definitions or
  incompatible link options will cause the one-time runner link to fail.
- `--amortize-link` works with split or PCH mode, not direct/single-step mode.
- Candidate files are still compiled and linked into temporary `.so` files;
  this is not an in-memory JIT.
- The optimization applies to the main Phase 3 candidate-testing loop. Some
  one-off validation work outside that loop still uses normal compilation.

## 13. Short meeting summary

```text
Problem:
  thousands of harness candidates + one unchanged large target
  -> repeatedly linking the target wastes time

Solution:
  load target `.so` or link target `.a` into a persistent runner once
  -> read the crash input once
  -> compile each candidate as a small plugin
  -> fork, load plugin, call LLVMFuzzerTestOneInput
  -> return crash status and log

Safety:
  candidates run in isolated child processes
  -> a crash does not kill the persistent runner

Combined optimization:
  PCH saves repeated header compilation
  linkage amortization saves repeated target linking/loading setup
```

The key idea is simple: **keep the large, unchanged environment alive and only
replace the small piece of harness logic that TreeReduce is modifying.**
