// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_escape at escape.c:50:7 in curl.h
// curl_free at escape.c:189:6 in curl.h
// curl_easy_cleanup at easy.c:837:6 in easy.h
// curl_strequal at strequal.c:76:5 in curl.h
// curl_strequal at strequal.c:76:5 in curl.h
// curl_strnequal at strequal.c:87:5 in curl.h
// curl_strnequal at strequal.c:87:5 in curl.h
// curl_escape at escape.c:36:7 in curl.h
// curl_unescape at escape.c:42:7 in curl.h
// curl_easy_escape at escape.c:50:7 in curl.h
// curl_easy_unescape at escape.c:163:7 in curl.h
// curl_strequal at strequal.c:76:5 in curl.h
// curl_strnequal at strequal.c:87:5 in curl.h
// curl_strequal at strequal.c:76:5 in curl.h
// curl_strnequal at strequal.c:87:5 in curl.h
// curl_escape at escape.c:36:7 in curl.h
// curl_unescape at escape.c:42:7 in curl.h
// curl_free at escape.c:189:6 in curl.h
// curl_free at escape.c:189:6 in curl.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_easy_escape at escape.c:50:7 in curl.h
// curl_easy_unescape at escape.c:163:7 in curl.h
// curl_free at escape.c:189:6 in curl.h
// curl_free at escape.c:189:6 in curl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "curl/curl.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_dummy_file(const uint8_t *data, size_t size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (fp) {
        fwrite(data, 1, size, fp);
        fclose(fp);
    }
}

static void remove_dummy_file(void) {
    unlink("./dummy_file");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Prepare strings from fuzzer input
    // Split input into two parts for string comparisons
    size_t split = Size / 2;
    char *str1 = (char *)malloc(split + 1);
    char *str2 = (char *)malloc(Size - split + 1);
    
    if (!str1 || !str2) {
        free(str1);
        free(str2);
        return 0;
    }
    
    memcpy(str1, Data, split);
    str1[split] = '\0';
    
    memcpy(str2, Data + split, Size - split);
    str2[Size - split] = '\0';
    
    // Test curl_strequal
    int result_equal = curl_strequal(str1, str2);
    (void)result_equal;
    
    // Test curl_strnequal with various lengths
    size_t n = Size % 256; // Limit n to reasonable size
    int result_nequal = curl_strnequal(str1, str2, n);
    (void)result_nequal;
    
    // Test with NULL pointers
    curl_strequal(NULL, NULL);
    curl_strnequal(NULL, NULL, n);
    
    // Test curl_escape and curl_unescape
    int escape_len = Size % 1024; // Limit length
    char *escaped = curl_escape(str1, escape_len);
    if (escaped) {
        char *unescaped = curl_unescape(escaped, 0);
        if (unescaped) {
            curl_free(unescaped);
        }
        curl_free(escaped);
    }
    
    // Test curl_easy_escape and curl_easy_unescape
    CURL *curl = curl_easy_init();
    if (curl) {
        int easy_escape_len = Size % 512;
        char *easy_escaped = curl_easy_escape(curl, str2, easy_escape_len);
        if (easy_escaped) {
            int outlength = 0;
            char *easy_unescaped = curl_easy_unescape(curl, easy_escaped, 0, &outlength);
            if (easy_unescaped) {
                curl_free(easy_unescaped);
            }
            curl_free(easy_escaped);
        }
        
        // Test with file-based input
        write_dummy_file(Data, Size);
        FILE *fp = fopen("./dummy_file", "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            
            if (file_size > 0) {
                char *file_content = (char *)malloc(file_size + 1);
                if (file_content) {
                    fread(file_content, 1, file_size, fp);
                    file_content[file_size] = '\0';
                    
                    // Test with file content
                    char *file_escaped = curl_easy_escape(curl, file_content, (int)file_size);
                    if (file_escaped) {
                        curl_free(file_escaped);
                    }
                    free(file_content);
                }
            }
            fclose(fp);
        }
        remove_dummy_file();
        
        curl_easy_cleanup(curl);
    }
    
    // Test edge cases
    curl_strequal(str1, NULL);
    curl_strequal(NULL, str2);
    
    curl_strnequal(str1, NULL, 0);
    curl_strnequal(NULL, str2, 0);
    
    // Test with zero length
    curl_escape(str1, 0);
    curl_unescape(str2, 0);
    
    if (curl) {
        curl_easy_escape(curl, str1, 0);
        curl_easy_unescape(curl, str2, 0, NULL);
    }
    
    free(str1);
    free(str2);
    
    return 0;
}
