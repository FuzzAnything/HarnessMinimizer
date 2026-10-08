// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open_v2 at sqlite3.c:174573:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172232:16 in sqlite3.h
// sqlite3_db_config at sqlite3.c:171839:16 in sqlite3.h
// sqlite3_file_control at sqlite3.c:175027:16 in sqlite3.h
// sqlite3_db_config at sqlite3.c:171839:16 in sqlite3.h
// sqlite3_create_function at sqlite3.c:172998:16 in sqlite3.h
// sqlite3_trace at sqlite3.c:173137:18 in sqlite3.h
// sqlite3_close at sqlite3.c:172232:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void dummy_trace(void *arg, const char *sql) {
    (void)arg;
    (void)sql;
}

static void dummy_func(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)ctx;
    (void)argc;
    (void)argv;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    int rc;
    const char *filename = "./dummy_file";
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;
    if (Size > 0) {
        fwrite(Data, 1, Size > 1024 ? 1024 : Size, fp);
    }
    fclose(fp);
    
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (Size > 0) {
        flags |= (Data[0] & 0x0F);
    }
    
    rc = sqlite3_open_v2(filename, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        if (db) sqlite3_close(db);
        remove(filename);
        return 0;
    }
    
    int op1 = SQLITE_DBCONFIG_LOOKASIDE;
    if (Size > 1) {
        op1 = Data[1] % 20;
    }
    sqlite3_db_config(db, op1, 0, 0);
    
    int file_op = 0;
    int dummy_arg = 0;
    if (Size > 2) {
        file_op = Data[2];
    }
    sqlite3_file_control(db, "main", file_op, &dummy_arg);
    
    int op2 = SQLITE_DBCONFIG_ENABLE_FKEY;
    if (Size > 3) {
        op2 = Data[3] % 20;
    }
    sqlite3_db_config(db, op2, 0, 0);
    
    const char *func_name = "fuzz_func";
    int nArg = 0;
    int eTextRep = SQLITE_UTF8;
    
    if (Size > 4) {
        nArg = Data[4] % 10;
        if (Size > 5) {
            eTextRep = Data[5] & 0x07;
        }
    }
    
    sqlite3_create_function(db, func_name, nArg, eTextRep, NULL, dummy_func, NULL, NULL);
    
    sqlite3_trace(db, dummy_trace, NULL);
    
    sqlite3_close(db);
    remove(filename);
    return 0;
}
