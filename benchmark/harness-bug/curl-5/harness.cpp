// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_msprintf at mprintf.c:1175:5 in mprintf.h
// curl_msprintf at mprintf.c:1175:5 in mprintf.h
// curl_mvsnprintf at mprintf.c:1077:5 in mprintf.h
// curl_mvsprintf at mprintf.c:1214:5 in mprintf.h
// curl_mprintf at mprintf.c:1194:5 in mprintf.h
// curl_mprintf at mprintf.c:1194:5 in mprintf.h
// curl_msnprintf at mprintf.c:1102:5 in mprintf.h
// curl_msnprintf at mprintf.c:1102:5 in mprintf.h
// curl_mfprintf at mprintf.c:1204:5 in mprintf.h
// curl_mfprintf at mprintf.c:1204:5 in mprintf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "curl/mprintf.h"
#include <stdarg.h>

static void helper_mvsnprintf(const char *fmt, ...) {
    char local_buffer[1024];
    va_list args;
    va_start(args, fmt);
    curl_mvsnprintf(local_buffer, sizeof(local_buffer), fmt, args);
    va_end(args);
}

static void helper_mvsprintf(const char *fmt, ...) {
    char local_buffer[1024];
    va_list args;
    va_start(args, fmt);
    curl_mvsprintf(local_buffer, fmt, args);
    va_end(args);
}

static void call_curl_mvsnprintf(const uint8_t *data, size_t size) {
    char buffer[1024];
    size_t maxlength = sizeof(buffer);
    
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        helper_mvsnprintf(format, 42, "test", 3.14);
        
        free(format);
    }
}

static void call_curl_mprintf(const uint8_t *data, size_t size) {
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        curl_mprintf(format);
        if (size > 4) {
            curl_mprintf(format, (int)data[0], (int)data[1]);
        }
        
        free(format);
    }
}

static void call_curl_msnprintf(const uint8_t *data, size_t size) {
    char buffer[1024];
    size_t maxlength = sizeof(buffer);
    
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        curl_msnprintf(buffer, maxlength, format);
        if (size > 8) {
            curl_msnprintf(buffer, maxlength, format, 
                          (int)data[0], (int)data[1], (int)data[2]);
        }
        
        free(format);
    }
}

static void call_curl_mfprintf(const uint8_t *data, size_t size) {
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        FILE *fd = fopen("./dummy_file", "w");
        if (fd) {
            curl_mfprintf(fd, format);
            if (size > 4) {
                curl_mfprintf(fd, format, (int)data[0], (int)data[1]);
            }
            fclose(fd);
        }
        
        free(format);
    }
}

static void call_curl_msprintf(const uint8_t *data, size_t size) {
    char buffer[1024];
    
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        curl_msprintf(buffer, format);
        if (size > 4) {
            curl_msprintf(buffer, format, (int)data[0], (int)data[1]);
        }
        
        free(format);
    }
}

static void call_curl_mvsprintf(const uint8_t *data, size_t size) {
    char buffer[1024];
    
    if (size > 0) {
        char *format = (char*)malloc(size + 1);
        if (!format) return;
        memcpy(format, data, size);
        format[size] = '\0';
        
        helper_mvsprintf(format, 42, "test", 3.14);
        
        free(format);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    call_curl_mvsnprintf(Data, Size);
    call_curl_mprintf(Data, Size);
    call_curl_msnprintf(Data, Size);
    call_curl_mfprintf(Data, Size);
    call_curl_msprintf(Data, Size);
    call_curl_mvsprintf(Data, Size);
    
    return 0;
}
