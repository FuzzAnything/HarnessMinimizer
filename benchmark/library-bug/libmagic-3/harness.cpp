/*
 * harness_000.cpp - libmagic ("file" command, Release 5.x) main API fuzzer.
 *
 * Target APIs (magic.h):
 *   - magic_open(int flags)              : open a magic set (flags from input)
 *   - magic_load(magic_t, const char *)  : load the compiled magic database
 *   - magic_setflags(magic_t, int)       : vary detection flags per input
 *   - magic_buffer(magic_t, void *, size_t) : core detection entry point
 *   - magic_error / magic_errno / magic_getflags : error & state queries
 *   - magic_close(magic_t)               : cleanup
 *
 * Design notes:
 *   - The compiled magic database is large; it is loaded exactly once into a
 *     process-lifetime magic_set (same pattern as the project's own
 *     fuzz/magic_fuzzer.c). Per-iteration flag changes are applied with
 *     magic_setflags() on the shared set, which is cheap and avoids
 *     re-parsing the database on every iteration.
 *   - Control bytes (flags + mode selector) are consumed from the END of the
 *     fuzzer input (FuzzedDataProvider consumes integrals from the back), so
 *     the payload prefix - where real file-format magic signatures live
 *     (ELF/PNG/ZIP/... headers start at offset 0) - remains intact for
 *     magic_buffer().
 *   - MAGIC_DEBUG is excluded from the derived flag mask: it makes libmagic
 *     print per-rule debug traces to stderr, which would dominate runtime.
 *   - A small fraction of inputs (mode-selected) exercises the full
 *     open/load/buffer/close lifecycle on a fresh magic_set, covering
 *     magic_open() with arbitrary flag combinations and magic_close().
 */

#include <fuzzer/FuzzedDataProvider.h>

#include <magic.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

// Process-lifetime magic set with the database loaded once.
magic_t g_magic = nullptr;
bool g_init_attempted = false;

// Resolve the compiled magic database robustly:
//   1. $MAGIC environment variable (standard libmagic override)
//   2. Known build/install locations
//   3. NULL -> libmagic compiled-in default path
const char *resolve_magic_db_path() {
    const char *env = getenv("MAGIC");
    if (env != nullptr && env[0] != '\0')
        return env;

    static const char *const kCandidates[] = {
        "/root/output/file/build/sanitizer/share/misc/magic.mgc",
        "/root/output/file/build/fuzzer/share/misc/magic.mgc",
        "/usr/local/share/misc/magic.mgc",
        "/usr/share/misc/magic.mgc",
    };
    for (const char *path : kCandidates) {
        FILE *f = fopen(path, "rb");
        if (f != nullptr) {
            fclose(f);
            return path;
        }
    }
    return nullptr;
}

// One-time initialization of the shared magic set.
bool ensure_magic_ready() {
    if (!g_init_attempted) {
        g_init_attempted = true;
        g_magic = magic_open(MAGIC_NONE);
        if (g_magic != nullptr &&
            magic_load(g_magic, resolve_magic_db_path()) == -1) {
            magic_close(g_magic);
            g_magic = nullptr;
        }
    }
    return g_magic != nullptr;
}

// All behavior-relevant settable flags except MAGIC_DEBUG (0x1), which
// produces per-rule stderr traces and would dominate the fuzzing runtime.
const uint32_t kFlagMask =
    MAGIC_SYMLINK | MAGIC_COMPRESS | MAGIC_DEVICES | MAGIC_MIME_TYPE |
    MAGIC_CONTINUE | MAGIC_CHECK | MAGIC_PRESERVE_ATIME | MAGIC_RAW |
    MAGIC_ERROR | MAGIC_MIME_ENCODING | MAGIC_APPLE | MAGIC_EXTENSION |
    MAGIC_COMPRESS_TRANSP | MAGIC_NO_COMPRESS_FORK |
    MAGIC_NO_CHECK_COMPRESS | MAGIC_NO_CHECK_TAR | MAGIC_NO_CHECK_SOFT |
    MAGIC_NO_CHECK_APPTYPE | MAGIC_NO_CHECK_ELF | MAGIC_NO_CHECK_TEXT |
    MAGIC_NO_CHECK_CDF | MAGIC_NO_CHECK_CSV | MAGIC_NO_CHECK_TOKENS |
    MAGIC_NO_CHECK_ENCODING | MAGIC_NO_CHECK_JSON | MAGIC_NO_CHECK_SIMH;

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 4 flag bytes + 1 mode byte + 1 payload byte.
    if (size < 6)
        return 0;

    if (!ensure_magic_ready())
        return 0;

    FuzzedDataProvider fdp(data, size);

    // Fixed-size control values first, taken from the END of the input so the
    // payload keeps its leading magic signatures (file headers at offset 0).
    const uint32_t raw_flags = fdp.ConsumeIntegral<uint32_t>();
    const uint8_t mode = fdp.ConsumeIntegral<uint8_t>();
    const int flags = static_cast<int>(raw_flags & kFlagMask);

    // Variable-size payload last: everything that is left, from the front.
    std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();
    if (payload.empty())
        return 0;

    switch (mode & 0x0F) {
    case 14: {
        // Fresh magic_set with fuzzed flags, analyzed without a loaded
        // database: covers magic_open() flag handling, the "no magic files
        // loaded" error path and magic_close(), without paying the cost of
        // loading the database.
        magic_t ms = magic_open(flags);
        if (ms != nullptr) {
            magic_buffer(ms, payload.data(), payload.size());
            magic_error(ms);
            magic_errno(ms);
            magic_close(ms);
        }
        break;
    }
    case 15: {
        // Full lifecycle: open with fuzzed flags, load the database, analyze,
        // close. Rare (1/16 of inputs) to keep the average iteration fast.
        magic_t ms = magic_open(flags);
        if (ms != nullptr) {
            if (magic_load(ms, resolve_magic_db_path()) != -1)
                magic_buffer(ms, payload.data(), payload.size());
            magic_close(ms);
        }
        break;
    }
    default: {
        // Common path: vary flags on the shared pre-loaded set and analyze
        // the payload (soft magic, ELF, CDF, text/encoding, JSON, CSV, TAR,
        // compression, MIME, extension, Apple, ... checks).
        magic_setflags(g_magic, flags);
        const char *result =
            magic_buffer(g_magic, payload.data(), payload.size());
        if (result == nullptr) {
            // Exercise the error reporting APIs on failure paths.
            magic_error(g_magic);
            magic_errno(g_magic);
        }
        magic_getflags(g_magic);
        break;
    }
    }

    return 0;
}

// Release the shared magic set at process exit (clean shutdown and covers
// magic_close() on the long-lived set as well).
__attribute__((destructor)) static void harness_cleanup() {
    if (g_magic != nullptr) {
        magic_close(g_magic);
        g_magic = nullptr;
    }
}

