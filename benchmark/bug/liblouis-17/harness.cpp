// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_backTranslate at lou_backTranslateString.c:159:1 in liblouis.h
// lou_registerTableResolver at compileTranslationTable.c:4865:1 in liblouis.h
// lou_getTypeformForEmphClass at compileTranslationTable.c:5244:1 in liblouis.h
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_compileString at compileTranslationTable.c:5430:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include "liblouis/liblouis.h"

#define MAX_INPUT_SIZE 4096
#define MAX_OUTPUT_SIZE 8192

static char **dummy_resolver(const char *table, const char *base) {
    return NULL;
}

static void write_dummy_file(const uint8_t *data, size_t size) {
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, data, size);
        close(fd);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Use first byte to select function
    uint8_t function_selector = Data[0] % 6;
    const uint8_t *fuzz_data = Data + 1;
    size_t fuzz_size = Size - 1;

    // Initialize common buffers
    widechar inbuf[MAX_INPUT_SIZE];
    widechar outbuf[MAX_OUTPUT_SIZE];
    formtype typeform[MAX_INPUT_SIZE];
    char spacing[MAX_OUTPUT_SIZE];
    int outputPos[MAX_INPUT_SIZE];
    int inputPos[MAX_OUTPUT_SIZE];
    int cursorPos = 0;
    
    // Set up input buffer
    size_t inlen = fuzz_size / sizeof(widechar);
    if (inlen > MAX_INPUT_SIZE) inlen = MAX_INPUT_SIZE;
    if (inlen > 0) {
        memcpy(inbuf, fuzz_data, inlen * sizeof(widechar));
    }
    
    // Initialize lengths
    int inlen_int = (int)inlen;
    int outlen_int = MAX_OUTPUT_SIZE;

    // Use a valid table list
    const char *tableList = "en-us-g2.ctb";

    switch (function_selector) {
        case 0: // lou_backTranslate
            lou_backTranslate(tableList, inbuf, &inlen_int, outbuf, &outlen_int,
                             typeform, spacing, outputPos, inputPos, &cursorPos, 0);
            break;
            
        case 1: // lou_registerTableResolver
            lou_registerTableResolver(dummy_resolver);
            break;
            
        case 2: // lou_getTypeformForEmphClass
            if (fuzz_size > 0) {
                char emphClass[256];
                size_t len = fuzz_size < 255 ? fuzz_size : 255;
                memcpy(emphClass, fuzz_data, len);
                emphClass[len] = '\0';
                lou_getTypeformForEmphClass(tableList, emphClass);
            }
            break;
            
        case 3: // lou_translateString
            lou_translateString(tableList, inbuf, &inlen_int, outbuf, &outlen_int,
                               typeform, spacing, 0);
            break;
            
        case 4: // lou_compileString
            if (fuzz_size > 0) {
                char inString[1024];
                size_t len = fuzz_size < 1023 ? fuzz_size : 1023;
                memcpy(inString, fuzz_data, len);
                inString[len] = '\0';
                // Write table data to dummy file first
                write_dummy_file(fuzz_data, fuzz_size);
                lou_compileString("./dummy_file", inString);
            }
            break;
            
        case 5: // lou_backTranslateString
            lou_backTranslateString(tableList, inbuf, &inlen_int, outbuf, &outlen_int,
                                   typeform, spacing, 0);
            break;
    }

    // Clean up dummy file
    unlink("./dummy_file");
    
    return 0;
}
