// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
// lou_hyphenate at lou_translateString.c:4066:1 in liblouis.h
// lou_charSize at compileTranslationTable.c:5425:1 in liblouis.h
// lou_readCharFromFile at compileTranslationTable.c:4352:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "liblouis/liblouis.h"

static void write_dummy_file(const uint8_t *data, size_t size) {
    FILE *f = fopen("./dummy_file", "wb");
    if (f) {
        fwrite(data, 1, size, f);
        fclose(f);
    }
}

static void remove_dummy_file(void) {
    remove("./dummy_file");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Function selector based on first byte
    uint8_t func_selector = Data[0] % 6;
    const uint8_t *fuzz_data = Data + 1;
    size_t fuzz_size = Size - 1;

    switch (func_selector) {
        case 0: {  // lou_charSize
            lou_charSize();
            break;
        }
        
        case 1: {  // lou_readCharFromFile
            if (fuzz_size == 0) break;
            
            write_dummy_file(fuzz_data, fuzz_size);
            int mode = 1;
            while (lou_readCharFromFile("./dummy_file", &mode) != EOF) {
                // Continue reading until EOF
            }
            remove_dummy_file();
            break;
        }
        
        case 2: {  // lou_translatePrehyphenated
            if (fuzz_size < 4) break;
            
            // Extract parameters from fuzz data
            size_t offset = 0;
            int inlen = (fuzz_data[offset] % 32) + 1;
            offset = (offset + 1) % fuzz_size;
            int outlen = (fuzz_data[offset] % 64) + 1;
            offset = (offset + 1) % fuzz_size;
            int mode = fuzz_data[offset] % 4;
            
            // Allocate buffers
            widechar *inbuf = (widechar *)malloc(inlen * sizeof(widechar));
            widechar *outbuf = (widechar *)malloc(outlen * sizeof(widechar));
            formtype *typeform = (formtype *)malloc(inlen * sizeof(formtype));
            char *spacing = (char *)malloc((inlen + 1) * sizeof(char));
            int *outputPos = (int *)malloc(inlen * sizeof(int));
            int *inputPos = (int *)malloc(outlen * sizeof(int));
            int cursorPos = 0;
            char *inputHyphens = (char *)malloc(inlen * sizeof(char));
            char *outputHyphens = (char *)malloc(outlen * sizeof(char));
            
            if (inbuf && outbuf && typeform && spacing && 
                outputPos && inputPos && inputHyphens && outputHyphens) {
                
                // Initialize buffers with fuzz data
                for (int i = 0; i < inlen && offset < fuzz_size; i++) {
                    inbuf[i] = fuzz_data[offset];
                    typeform[i] = fuzz_data[offset] % 256;
                    spacing[i] = fuzz_data[offset] % 2;
                    inputHyphens[i] = fuzz_data[offset] % 2;
                    offset = (offset + 1) % fuzz_size;
                }
                
                for (int i = 0; i < outlen && offset < fuzz_size; i++) {
                    outputHyphens[i] = fuzz_data[offset] % 2;
                    offset = (offset + 1) % fuzz_size;
                }
                
                // Call function
                lou_translatePrehyphenated("en-us-g2.ctb", inbuf, &inlen, outbuf, &outlen,
                                          typeform, spacing, outputPos, inputPos, &cursorPos,
                                          inputHyphens, outputHyphens, mode);
            }
            
            // Cleanup
            free(inbuf);
            free(outbuf);
            free(typeform);
            free(spacing);
            free(outputPos);
            free(inputPos);
            free(inputHyphens);
            free(outputHyphens);
            break;
        }
        
        case 3: {  // lou_translateString
            if (fuzz_size < 3) break;
            
            size_t offset = 0;
            int inlen = (fuzz_data[offset] % 32) + 1;
            offset = (offset + 1) % fuzz_size;
            int outlen = (fuzz_data[offset] % 64) + 1;
            offset = (offset + 1) % fuzz_size;
            int mode = fuzz_data[offset] % 4;
            
            widechar *inbuf = (widechar *)malloc(inlen * sizeof(widechar));
            widechar *outbuf = (widechar *)malloc(outlen * sizeof(widechar));
            formtype *typeform = NULL;
            char *spacing = NULL;
            
            // Sometimes allocate typeform and spacing
            if ((fuzz_data[offset] % 2) && inlen > 0) {
                typeform = (formtype *)malloc(inlen * sizeof(formtype));
                spacing = (char *)malloc((inlen + 1) * sizeof(char));
                
                if (typeform && spacing) {
                    for (int i = 0; i < inlen && offset < fuzz_size; i++) {
                        typeform[i] = fuzz_data[offset] % 256;
                        spacing[i] = fuzz_data[offset] % 2;
                        offset = (offset + 1) % fuzz_size;
                    }
                }
            }
            
            if (inbuf && outbuf) {
                for (int i = 0; i < inlen && offset < fuzz_size; i++) {
                    inbuf[i] = fuzz_data[offset];
                    offset = (offset + 1) % fuzz_size;
                }
                
                lou_translateString("en-us-g2.ctb", inbuf, &inlen, outbuf, &outlen,
                                   typeform, spacing, mode);
            }
            
            free(inbuf);
            free(outbuf);
            free(typeform);
            free(spacing);
            break;
        }
        
        case 4: {  // lou_translate
            if (fuzz_size < 4) break;
            
            size_t offset = 0;
            int inlen = (fuzz_data[offset] % 32) + 1;
            offset = (offset + 1) % fuzz_size;
            int outlen = (fuzz_data[offset] % 64) + 1;
            offset = (offset + 1) % fuzz_size;
            int cursorPos = fuzz_data[offset] % (inlen + 1);
            offset = (offset + 1) % fuzz_size;
            int mode = fuzz_data[offset] % 4;
            
            widechar *inbuf = (widechar *)malloc(inlen * sizeof(widechar));
            widechar *outbuf = (widechar *)malloc(outlen * sizeof(widechar));
            formtype *typeform = (formtype *)malloc(outlen * sizeof(formtype));
            char *spacing = (char *)malloc(inlen * sizeof(char));
            int *outputPos = (int *)malloc(inlen * sizeof(int));
            int *inputPos = (int *)malloc(outlen * sizeof(int));
            
            if (inbuf && outbuf && typeform && spacing && outputPos && inputPos) {
                // Initialize typeform with zeros as recommended
                memset(typeform, 0, outlen * sizeof(formtype));
                
                for (int i = 0; i < inlen && offset < fuzz_size; i++) {
                    inbuf[i] = fuzz_data[offset];
                    spacing[i] = fuzz_data[offset] % 2;
                    offset = (offset + 1) % fuzz_size;
                }
                
                lou_translate("en-us-g2.ctb", inbuf, &inlen, outbuf, &outlen,
                             typeform, spacing, outputPos, inputPos, &cursorPos, mode);
            }
            
            free(inbuf);
            free(outbuf);
            free(typeform);
            free(spacing);
            free(outputPos);
            free(inputPos);
            break;
        }
        
        case 5: {  // lou_hyphenate
            if (fuzz_size < 2) break;
            
            size_t offset = 0;
            int inlen = (fuzz_data[offset] % 32) + 1;
            offset = (offset + 1) % fuzz_size;
            int mode = fuzz_data[offset] % 2;
            
            widechar *inbuf = (widechar *)malloc(inlen * sizeof(widechar));
            char *hyphens = (char *)malloc(inlen * sizeof(char));
            
            if (inbuf && hyphens) {
                for (int i = 0; i < inlen && offset < fuzz_size; i++) {
                    // Ensure input is letters only (basic ASCII letters)
                    inbuf[i] = (fuzz_data[offset] % 26) + 'a';
                    offset = (offset + 1) % fuzz_size;
                }
                
                lou_hyphenate("en-us-g2.ctb", inbuf, inlen, hyphens, mode);
            }
            
            free(inbuf);
            free(hyphens);
            break;
        }
    }
    
    return 0;
}
