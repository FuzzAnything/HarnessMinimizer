// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_backTranslate at lou_backTranslateString.c:159:1 in liblouis.h
// lou_hyphenate at lou_translateString.c:4066:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "liblouis/liblouis.h"

static void init_widechar_buffer(const uint8_t *data, size_t size, widechar **buf, int *len) {
    if (size == 0) {
        *len = 0;
        *buf = NULL;
        return;
    }
    *len = size / sizeof(widechar);
    if (*len == 0) *len = 1;
    *buf = (widechar *)malloc(*len * sizeof(widechar));
    if (!*buf) {
        *len = 0;
        return;
    }
    size_t copy_size = (size < *len * sizeof(widechar)) ? size : *len * sizeof(widechar);
    memcpy(*buf, data, copy_size);
}

static void init_formtype_buffer(int len, formtype **buf) {
    if (len <= 0) {
        *buf = NULL;
        return;
    }
    *buf = (formtype *)malloc(len * sizeof(formtype));
    if (*buf) {
        memset(*buf, 0, len * sizeof(formtype));
    }
}

static void init_char_buffer(int len, char **buf) {
    if (len <= 0) {
        *buf = NULL;
        return;
    }
    *buf = (char *)malloc(len * sizeof(char));
    if (*buf) {
        memset(*buf, 0, len * sizeof(char));
    }
}

static void init_int_buffer(int len, int **buf) {
    if (len <= 0) {
        *buf = NULL;
        return;
    }
    *buf = (int *)malloc(len * sizeof(int));
    if (*buf) {
        memset(*buf, 0, len * sizeof(int));
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Use first byte to select function and mode
    uint8_t selector = Data[0];
    const uint8_t *fuzz_data = Data + 1;
    size_t fuzz_size = Size - 1;

    // Common parameters
    const char *tableList = "en-us-g2.ctb";
    int mode = selector & 0x0F;
    
    // Initialize input buffer
    widechar *inbuf = NULL;
    int inlen = 0;
    init_widechar_buffer(fuzz_data, fuzz_size, &inbuf, &inlen);
    if (!inbuf && inlen > 0) return 0;

    // Output buffer size (heuristic: 4x input length, min 64, max 4096)
    int outlen_alloc = inlen * 4;
    if (outlen_alloc < 64) outlen_alloc = 64;
    if (outlen_alloc > 4096) outlen_alloc = 4096;
    widechar *outbuf = (widechar *)malloc(outlen_alloc * sizeof(widechar));
    if (!outbuf) {
        free(inbuf);
        return 0;
    }
    int outlen = outlen_alloc;

    // Function selection
    switch ((selector >> 4) % 6) {
        case 0: { // lou_translateString
            formtype *typeform = NULL;
            char *spacing = NULL;
            
            if (selector & 0x10) {
                init_formtype_buffer(inlen, &typeform);
            }
            if (selector & 0x20) {
                init_char_buffer(inlen + 1, &spacing);
            }
            
            lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen,
                               typeform, spacing, mode);
            
            free(typeform);
            free(spacing);
            break;
        }
        
        case 1: { // lou_backTranslate
            formtype *typeform = NULL;
            char *spacing = NULL;
            int *outputPos = NULL;
            int *inputPos = NULL;
            int cursorPos = 0;
            
            if (selector & 0x10) {
                init_formtype_buffer(inlen, &typeform);
            }
            if (selector & 0x20) {
                init_char_buffer(outlen_alloc, &spacing);
            }
            if (selector & 0x40) {
                init_int_buffer(inlen, &outputPos);
                init_int_buffer(outlen_alloc, &inputPos);
            }
            
            lou_backTranslate(tableList, inbuf, &inlen, outbuf, &outlen,
                             typeform, spacing, outputPos, inputPos, &cursorPos, mode);
            
            free(typeform);
            free(spacing);
            free(outputPos);
            free(inputPos);
            break;
        }
        
        case 2: { // lou_hyphenate
            char *hyphens = (char *)malloc((inlen + 1) * sizeof(char));
            if (hyphens) {
                lou_hyphenate(tableList, inbuf, inlen, hyphens, mode);
                free(hyphens);
            }
            break;
        }
        
        case 3: { // lou_backTranslateString
            formtype *typeform = NULL;
            char *spacing = NULL;
            
            if (selector & 0x10) {
                init_formtype_buffer(outlen_alloc, &typeform);
            }
            if (selector & 0x20) {
                init_char_buffer(outlen_alloc, &spacing);
            }
            
            lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen,
                                   typeform, spacing, mode);
            
            free(typeform);
            free(spacing);
            break;
        }
        
        case 4: { // lou_translate
            formtype *typeform = NULL;
            char *spacing = NULL;
            int *outputPos = NULL;
            int *inputPos = NULL;
            int cursorPos = 0;
            
            if (selector & 0x10) {
                init_formtype_buffer(outlen_alloc, &typeform);
            }
            if (selector & 0x20) {
                init_char_buffer(inlen, &spacing);
            }
            if (selector & 0x40) {
                init_int_buffer(inlen, &outputPos);
                init_int_buffer(outlen_alloc, &inputPos);
            }
            
            lou_translate(tableList, inbuf, &inlen, outbuf, &outlen,
                         typeform, spacing, outputPos, inputPos, &cursorPos, mode);
            
            free(typeform);
            free(spacing);
            free(outputPos);
            free(inputPos);
            break;
        }
        
        case 5: { // lou_translatePrehyphenated
            formtype *typeform = NULL;
            char *spacing = NULL;
            int *outputPos = NULL;
            int *inputPos = NULL;
            int cursorPos = 0;
            char *inputHyphens = NULL;
            char *outputHyphens = NULL;
            
            if (selector & 0x10) {
                init_formtype_buffer(outlen_alloc, &typeform);
            }
            if (selector & 0x20) {
                init_char_buffer(inlen, &spacing);
            }
            if (selector & 0x40) {
                init_int_buffer(inlen, &outputPos);
                init_int_buffer(outlen_alloc, &inputPos);
            }
            if (selector & 0x80) {
                init_char_buffer(inlen + 1, &inputHyphens);
                init_char_buffer(outlen_alloc + 1, &outputHyphens);
            }
            
            lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen,
                                      typeform, spacing, outputPos, inputPos, &cursorPos,
                                      inputHyphens, outputHyphens, mode);
            
            free(typeform);
            free(spacing);
            free(outputPos);
            free(inputPos);
            free(inputHyphens);
            free(outputHyphens);
            break;
        }
    }
    
    // Cleanup
    free(inbuf);
    free(outbuf);
    
    return 0;
}
