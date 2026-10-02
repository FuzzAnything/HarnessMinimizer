// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_prepare_v2 at sqlite3.c:132472:16 in sqlite3.h
// sqlite3_bind_blob at sqlite3.c:79985:16 in sqlite3.h
// sqlite3_bind_null at sqlite3.c:80032:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79161:16 in sqlite3.h
// sqlite3_reset at sqlite3.c:78392:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78363:16 in sqlite3.h
// sqlite3_vtab_nochange at sqlite3.c:79256:16 in sqlite3.h
// sqlite3_result_value at sqlite3.c:78892:17 in sqlite3.h
// sqlite3_result_blob at sqlite3.c:78699:17 in sqlite3.h
// sqlite3_result_blob at sqlite3.c:78699:17 in sqlite3.h
// sqlite3_result_blob at sqlite3.c:78699:17 in sqlite3.h
// sqlite3_result_blob at sqlite3.c:78699:17 in sqlite3.h
// sqlite3_result_int at sqlite3.c:78760:17 in sqlite3.h
// sqlite3_result_error at sqlite3.c:78742:17 in sqlite3.h
// sqlite3_result_error at sqlite3.c:78742:17 in sqlite3.h
// sqlite3_result_error at sqlite3.c:78742:17 in sqlite3.h
// sqlite3_result_error_code at sqlite3.c:78932:17 in sqlite3.h
// sqlite3_open at sqlite3.c:174566:16 in sqlite3.h
// sqlite3_create_function at sqlite3.c:172998:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"

static void dummy_destructor(void *ptr) {
    /* Do nothing - used for SQLITE_STATIC or SQLITE_TRANSIENT */
}

static sqlite3_context *saved_ctx = NULL;
static sqlite3_value *saved_val = NULL;
static int dummy_func_called = 0;

static void dummy_func(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    saved_ctx = ctx;
    if (argc > 0) {
        saved_val = argv[0];
    }
    dummy_func_called = 1;
}

static void test_sqlite3_result_value(sqlite3_context *ctx, sqlite3_value *val) {
    sqlite3_result_value(ctx, val);
}

static void test_sqlite3_result_blob(sqlite3_context *ctx, const uint8_t *data, size_t size) {
    if (size > 0) {
        /* Use different destructor modes based on input */
        if (size % 3 == 0) {
            sqlite3_result_blob(ctx, data, (int)(size % 1024), SQLITE_STATIC);
        } else if (size % 3 == 1) {
            sqlite3_result_blob(ctx, data, (int)(size % 1024), SQLITE_TRANSIENT);
        } else {
            sqlite3_result_blob(ctx, data, (int)(size % 1024), dummy_destructor);
        }
    } else {
        sqlite3_result_blob(ctx, NULL, 0, SQLITE_STATIC);
    }
}

static void test_sqlite3_result_int(sqlite3_context *ctx, const uint8_t *data, size_t size) {
    int value = 0;
    if (size >= sizeof(int)) {
        memcpy(&value, data, sizeof(int));
    } else if (size > 0) {
        value = data[0];
    }
    sqlite3_result_int(ctx, value);
}

static void test_sqlite3_result_error(sqlite3_context *ctx, const uint8_t *data, size_t size) {
    if (size > 0) {
        /* Use negative length for null-terminated, positive for fixed length */
        int len = (int)(size % 256);
        if (len % 2 == 0) {
            sqlite3_result_error(ctx, (const char*)data, -1);
        } else {
            sqlite3_result_error(ctx, (const char*)data, len);
        }
    } else {
        sqlite3_result_error(ctx, "fuzz error", -1);
    }
}

static void test_sqlite3_result_error_code(sqlite3_context *ctx, const uint8_t *data, size_t size) {
    int errcode = SQLITE_ERROR;
    if (size >= sizeof(int)) {
        memcpy(&errcode, data, sizeof(int));
    } else if (size > 0) {
        errcode = data[0];
    }
    sqlite3_result_error_code(ctx, errcode);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    static sqlite3 *db = NULL;
    
    /* Initialize sqlite3 database once */
    if (!initialized) {
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            return 0;
        }
        /* Register the dummy function */
        sqlite3_create_function(db, "dummy_func", 1, SQLITE_UTF8, NULL, dummy_func, NULL, NULL);
        initialized = 1;
    }
    
    if (Size == 0) {
        return 0;
    }
    
    /* Reset the static variables */
    saved_ctx = NULL;
    saved_val = NULL;
    dummy_func_called = 0;
    
    /* Create a statement to call the function */
    sqlite3_stmt *stmt;
    const char *sql = "SELECT dummy_func(?)";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        /* Bind the fuzzed data as a blob */
        if (Size > 0) {
            sqlite3_bind_blob(stmt, 1, Data, (int)(Size % 1024), SQLITE_STATIC);
        } else {
            sqlite3_bind_null(stmt, 1);
        }
        
        /* Execute to trigger the function call */
        sqlite3_step(stmt);
        
        /* Reset the statement for cleanup */
        sqlite3_reset(stmt);
        sqlite3_finalize(stmt);
    }
    
    /* If we have a valid context and value from the function call, test the APIs */
    if (dummy_func_called && saved_ctx) {
        /* Use first byte to choose which function to test */
        uint8_t selector = Data[0];
        const uint8_t *fuzz_data = Data + 1;
        size_t fuzz_size = Size - 1;
        
        if (fuzz_size == 0 && Size > 0) {
            fuzz_data = Data;
            fuzz_size = Size;
        }
        
        switch (selector % 6) {
            case 0:
                if (saved_val) {
                    test_sqlite3_result_value(saved_ctx, saved_val);
                }
                break;
            case 1:
                sqlite3_vtab_nochange(saved_ctx);
                break;
            case 2:
                test_sqlite3_result_blob(saved_ctx, fuzz_data, fuzz_size);
                break;
            case 3:
                test_sqlite3_result_int(saved_ctx, fuzz_data, fuzz_size);
                break;
            case 4:
                test_sqlite3_result_error(saved_ctx, fuzz_data, fuzz_size);
                break;
            case 5:
                test_sqlite3_result_error_code(saved_ctx, fuzz_data, fuzz_size);
                break;
        }
    }
    
    return 0;
}
