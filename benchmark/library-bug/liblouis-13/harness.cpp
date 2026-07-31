//
// liblouis Braille Translation and Back-Translation Library
//


#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <liblouis/internal.h>
#include <liblouis/liblouis.h>

#define LANGUAGE "en"

static int initialized = 0;

#define BOLDRED(x) "\x1b[31m\x1b[1m" x "\x1b[0m"

static const char *table_default;

static void __attribute__((destructor))
free_ressources(void) {
    lou_free();
}

static void
avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int inputLen = 0;
    int outputLen = 0;
    static int counter = 0;

    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
    }

    if (size < 512) {
        return 0;
    }

    // Write first 512 bytes of fuzz data to a table file.
    char new_file[256];
    snprintf(new_file, sizeof(new_file), "/tmp/libfuzzer-%d.ctb", counter);
    counter++;

    FILE *fp = fopen(new_file, "wb");
    if (!fp) {
        return 0;
    }

    fwrite(data, 512, 1, fp);
    fclose(fp);

    // Adjust data pointer to after the table file data.
    data += 512;
    size -= 512;

    // Check if this table works; otherwise bail.
    if (lou_checkTable(new_file) == 0) {
        lou_free();
        unlink(new_file);
        return 0;
    }

    table_default = new_file;

    char *mutable_data = strndup(reinterpret_cast<const char *>(data), size);
    if (!mutable_data) {
        unlink(new_file);
        lou_free();
        return 0;
    }

    widechar *inputText = static_cast<widechar *>(
        malloc((size * 16 + 1) * sizeof(widechar))
    );

    if (!inputText) {
        free(mutable_data);
        unlink(new_file);
        lou_free();
        return 0;
    }

    int len = static_cast<int>(_lou_extParseChars(mutable_data, inputText));
    free(mutable_data);

    if (len <= 0) {
        free(inputText);
        unlink(new_file);
        lou_free();
        return 0;
    }

    assert(len <= static_cast<int>(size * 16));

    inputLen = len;
    outputLen = len * 16;

    widechar *outputText = static_cast<widechar *>(
        malloc((outputLen + 1) * sizeof(widechar))
    );

    if (!outputText) {
        free(inputText);
        unlink(new_file);
        lou_free();
        return 0;
    }

    lou_translateString(
        table_default,
        inputText,
        &inputLen,
        outputText,
        &outputLen,
        NULL,
        NULL,
        ucBrl
    );

    free(inputText);
    free(outputText);

    lou_free();
    unlink(new_file);

    return 0;
}