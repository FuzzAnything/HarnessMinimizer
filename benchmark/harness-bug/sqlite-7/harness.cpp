// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_str_vappendf at sqlite3.c:18175:17 in sqlite3.h
// sqlite3_vmprintf at sqlite3.c:19324:18 in sqlite3.h
// sqlite3_str_new at sqlite3.c:19276:25 in sqlite3.h
// sqlite3_str_appendf at sqlite3.c:19484:17 in sqlite3.h
// sqlite3_config at sqlite3.c:171315:16 in sqlite3.h
// sqlite3_log at sqlite3.c:19443:17 in sqlite3.h
// sqlite3_snprintf at sqlite3.c:19388:18 in sqlite3.h
// sqlite3_mprintf at sqlite3.c:19348:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17470:17 in sqlite3.h
// sqlite3_free at sqlite3.c:17470:17 in sqlite3.h
// sqlite3_str_finish at sqlite3.c:19191:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17470:17 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

static void dummy_log_callback(void *pArg, int iErrCode, const char *zMsg) {
    /* Dummy callback to avoid null pointer dereference */
    (void)pArg;
    (void)iErrCode;
    (void)zMsg;
}

static void test_vappendf(sqlite3_str *str, const char *format, ...) {
    va_list args;
    va_start(args, format);
    sqlite3_str_vappendf(str, format, args);
    va_end(args);
}

static char *test_vmprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *result = sqlite3_vmprintf(format, args);
    va_end(args);
    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize sqlite3_str object */
    sqlite3_str *str = sqlite3_str_new(NULL);
    if (!str) return 0;
    
    /* Prepare format string and arguments from fuzzer input */
    char format_buf[256];
    char arg_buf[256];
    int int_arg = 0;
    double double_arg = 0.0;
    const char *str_arg = NULL;
    
    /* Use first 255 bytes for format string (null-terminated) */
    size_t fmt_len = Size < 255 ? Size : 255;
    memcpy(format_buf, Data, fmt_len);
    format_buf[fmt_len] = '\0';
    
    /* Use remaining data for arguments if available */
    if (Size > fmt_len) {
        size_t arg_len = Size - fmt_len;
        if (arg_len > 255) arg_len = 255;
        memcpy(arg_buf, Data + fmt_len, arg_len);
        arg_buf[arg_len] = '\0';
        str_arg = arg_buf;
        
        /* Derive integer and double from input bytes */
        if (arg_len >= 4) {
            int_arg = *(int*)(Data + fmt_len);
        }
        if (arg_len >= 8) {
            double_arg = *(double*)(Data + fmt_len);
        }
    } else {
        str_arg = "default";
    }
    
    /* Test sqlite3_str_appendf */
    sqlite3_str_appendf(str, format_buf, str_arg, int_arg, double_arg);
    
    /* Test sqlite3_str_vappendf using helper function */
    test_vappendf(str, format_buf, str_arg, int_arg, double_arg);
    
    /* Test sqlite3_log - set a dummy callback first */
    sqlite3_config(SQLITE_CONFIG_LOG, dummy_log_callback, NULL);
    sqlite3_log(0, format_buf, str_arg, int_arg, double_arg);
    
    /* Test sqlite3_snprintf */
    char snprintf_buf[512];
    sqlite3_snprintf(sizeof(snprintf_buf), snprintf_buf, 
                     format_buf, str_arg, int_arg, double_arg);
    
    /* Test sqlite3_mprintf */
    char *mprintf_result = sqlite3_mprintf(format_buf, str_arg, int_arg, double_arg);
    if (mprintf_result) {
        sqlite3_free(mprintf_result);
    }
    
    /* Test sqlite3_vmprintf using helper function */
    char *vmprintf_result = test_vmprintf(format_buf, str_arg, int_arg, double_arg);
    if (vmprintf_result) {
        sqlite3_free(vmprintf_result);
    }
    
    /* Cleanup */
    char *str_result = sqlite3_str_finish(str);
    if (str_result) {
        sqlite3_free(str_result);
    }
    
    return 0;
}
