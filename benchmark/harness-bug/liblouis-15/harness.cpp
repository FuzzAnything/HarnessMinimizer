// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_getTableInfo at metadata.c:1142:1 in liblouis.h
// lou_freeTableInfo at metadata.c:1167:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
// lou_freeEmphClasses at compileTranslationTable.c:5095:1 in liblouis.h
// lou_indexTables at metadata.c:945:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
// lou_freeEmphClasses at compileTranslationTable.c:5095:1 in liblouis.h
// lou_getTableInfo at metadata.c:1142:1 in liblouis.h
// lou_freeTableInfo at metadata.c:1167:1 in liblouis.h
// lou_findTable at metadata.c:1063:1 in liblouis.h
// lou_dotsToChar at lou_translateString.c:4150:1 in liblouis.h
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
    
    // Ensure lou_indexTables is called before lou_findTable
    static int tables_indexed = 0;
    if (!tables_indexed) {
        lou_indexTables(NULL);
        tables_indexed = 1;
    }
    
    // Split input into parts for different parameters
    size_t part_size = Size / 6;
    if (part_size < 1) part_size = 1;
    
    // 1. Test lou_getEmphClasses and lou_freeEmphClasses
    char tableList[256] = {0};
    size_t tableList_len = (part_size < 255) ? part_size : 255;
    memcpy(tableList, Data, tableList_len);
    tableList[tableList_len] = '\0';
    
    const char **emph_classes = lou_getEmphClasses(tableList);
    if (emph_classes) {
        lou_freeEmphClasses(emph_classes);
    }
    
    // 2. Test lou_getTableInfo and lou_freeTableInfo
    char table[256] = {0};
    char key[256] = {0};
    
    size_t table_len = (part_size < 255) ? part_size : 255;
    memcpy(table, Data + part_size, table_len);
    table[table_len] = '\0';
    
    size_t key_len = (part_size < 255) ? part_size : 255;
    memcpy(key, Data + 2*part_size, key_len);
    key[key_len] = '\0';
    
    char *table_info = lou_getTableInfo(table, key);
    if (table_info) {
        lou_freeTableInfo(table_info);
    }
    
    // 3. Test lou_findTable
    char query[256] = {0};
    size_t query_len = (part_size < 255) ? part_size : 255;
    memcpy(query, Data + 3*part_size, query_len);
    query[query_len] = '\0';
    
    char *found_table = lou_findTable(query);
    if (found_table) {
        free(found_table);
    }
    
    // 4. Test lou_dotsToChar
    // Use remaining data for inbuf
    size_t remaining = Size - 4*part_size;
    if (remaining > 0) {
        // Allocate buffers
        size_t wc_size = remaining / sizeof(widechar);
        if (wc_size > 0) {
            widechar *inbuf = (widechar*)malloc(wc_size * sizeof(widechar));
            widechar *outbuf = (widechar*)malloc(wc_size * sizeof(widechar));
            
            if (inbuf && outbuf) {
                // Copy data to inbuf
                memcpy(inbuf, Data + 4*part_size, wc_size * sizeof(widechar));
                
                // Call with mode = 0 (deprecated)
                lou_dotsToChar(tableList, inbuf, outbuf, wc_size, 0);
                
                free(inbuf);
                free(outbuf);
            }
        }
    }
    
    // 5. Test with file-based operations
    write_dummy_file(Data, (Size < 1024) ? Size : 1024);
    
    // Test lou_getTableInfo with dummy file as table
    char *dummy_table_info = lou_getTableInfo("./dummy_file", "test");
    if (dummy_table_info) {
        lou_freeTableInfo(dummy_table_info);
    }
    
    // Test lou_getEmphClasses with dummy file
    const char **dummy_emph = lou_getEmphClasses("./dummy_file");
    if (dummy_emph) {
        lou_freeEmphClasses(dummy_emph);
    }
    
    remove_dummy_file();
    
    return 0;
}
