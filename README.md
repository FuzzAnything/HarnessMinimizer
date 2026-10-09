# HarnessMinimizer

HarnessMinimizer minimizes crashing C/C++ fuzz harnesses while preserving the crash.
It can be used through a command-line interface
(CLI) and a Python API.

## Installation

```bash
docker build -t '<image-name>' - < Dockerfile
docker run -d --name '<container-name>' --init '<image-name>' sleep infinity
docker exec -it '<container-name>' bash
```

The image fetches the GitHub `main` branch.
To select a specific commit, tag, or branch, add `--build-arg HARNESSMINIMIZER_REF='<revision>'` to `docker build`.
Docker may reuse a cached checkout; use `--no-cache`
to fetch again.

Install the Python package and activate its environment using uv.

```bash
uv sync
source .venv/bin/activate
```

## Reduce a harness

Replace the absolute paths below with your harness, crash input, target library,
and output locations inside the container, and replace `target` with the library
name. The harness and crash input can be in different directories. If the harness
opens runtime files using relative paths, run from the working directory those paths require.

Optimized pipeline:

```bash
harnessminimizer /path/to/harness.cpp \
  --tool treereduce \
  --compile-flags="-I/path/to/library/include" \
  --link-flags="-L/path/to/library/lib -ltarget" \
  --crash-input /path/to/inputs/crash-input \
  --pch --amortize-link --no-symbolize --stable \
  -o /path/to/output/reduced.cpp
```

Unoptimized pipeline:

```bash
harnessminimizer /path/to/harness.cpp \
  --tool treereduce \
  --compile-flags="-I/path/to/library/include" \
  --link-flags="-L/path/to/library/lib -ltarget" \
  --crash-input /path/to/inputs/crash-input \
  --split --symbolize --stable \
  -o /path/to/output/reduced.cpp
```

The default is the **unoptimized configuration**: **split compilation** with
**symbolization on**, **PCH off**, and **amortized linking off**. HarnessMinimizer
uses **treereduce** and **60 workers** by default. Replace `--tool treereduce`
with `--tool perses`, `--tool wdd`, or `--tool cdd` to use an optional engine.
Profiling and stable mode are **off** unless explicitly enabled.

| Argument | Purpose |
| --- | --- |
| `harness` | Required path to the original harness source. |
| `-o`, `--output` | Required destination for the reduced harness. |
| `--crash-input` | Optional crashing input file passed to the harness. |
| `--compile-flags="..."` | Compiler flags, such as include paths, defines, and language standard. |
| `--link-flags="..."` | Linker flags, such as library paths, library names, or full archive paths. |
| `--tool` | Reduction engine: `treereduce` (default), `perses`, `wdd`, or `cdd`. |
| `-j`, `--jobs` | Requested concurrent candidate checks: 1–63, default 60. |
| `--direct`, `--split`, `--pch` | Compile and link in one step; compile then link separately (default); or use precompiled headers with separate compilation and linking. |
| `--amortize-link` | Reuse a persistent runner and shared/static target libraries. |
| `--stable` | Repeat engine passes until their stopping conditions are reached. |
| `--symbolize`, `--no-symbolize` | Enable symbolized candidate checks (default), or disable them for faster reduction. These flags are mutually exclusive. |
| `--work-dir` | Directory for intermediate files; a temporary directory is created by default. |
| `--profile` | Record candidate timings and reduction throughput for diagnostics. |
| `--debug` | Log candidate compilation and crash-check details. |

Choose only one of `--direct`, `--split`, and `--pch`. `--amortize-link` requires
split or PCH mode and shared or static target libraries in the link flags.
Use the `--compile-flags="..."` and `--link-flags="..."` spelling shown above for
values beginning with `-`. See `harnessminimizer --help` for the full option list.
The CLI copies any required generated header files beside the output harness.

### Python API

Run the same reduction from Python and check that it succeeded before using the result.

```python
from harnessminimizer import ReductionConfig, reduce_with_config

result = reduce_with_config(ReductionConfig(
    harness_path="/path/to/harness.cpp",
    tool="treereduce",
    crash_input="/path/to/inputs/crash-input",
    compile_flags="-I/path/to/library/include",
    link_flags="-L/path/to/library/lib -ltarget",
    compilation_mode="pch",
    amortize_link=True,
    symbolize=False,
    stable=True,
))
if not result.success:
    raise RuntimeError("Reduction did not preserve the crash")
print(result.reduced_harness)
```

The API uses the same defaults as the CLI. If you move the returned harness, copy
the files in `result.generated_headers` alongside it.

## Reference

Supported reduction engines:

- Treereduce: [https://github.com/langston-barrett/treereduce](https://github.com/langston-barrett/treereduce)
- Perses, WDD and CDD: [https://github.com/uw-pluverse/perses](https://github.com/uw-pluverse/perses)

## License

HarnessMinimizer is distributed as a whole under AGPL-3.0-only or a separately
negotiated commercial license: see [LICENSE](LICENSE). Applicable upstream
license conditions and notices remain in effect: see
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) for component details.

Perses is an optional external program licensed under GPL-3.0-or-later.
It is not part of the HarnessMinimizer distribution.
HarnessMinimizer does not bundle Perses source or binaries: users obtain and
build Perses separately, and HarnessMinimizer invokes its command-line interface
using candidate files and a checker script. Our installer and adapter scripts are
covered by HarnessMinimizer's license and a commercial license for HarnessMinimizer
does not grant exceptions to Perses's license. See the
[upstream Perses license](https://github.com/uw-pluverse/perses/blob/6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2/LICENSE).

If you use or integrate HarnessMinimizer, we appreciate an acknowledgment in your project documentation or research publications.
