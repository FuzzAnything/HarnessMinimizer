#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <liblouis/liblouis.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Set up a dummy data path
    lou_setDataPath("./dummy_file");

    // Call lou_indexTables before lou_findTable
    const char *tables[] = {
        "/root/HarnessMinimizer/benchmark/library-bug/liblouis-9/build/sanitizer/share/liblouis/tables/afr-za-g1.ctb",
        NULL
    };

    lou_indexTables(tables);

    // Use the input data to create a query string
    char *query = (char *)malloc(Size + 1);
    if (!query) return 0;

    memcpy(query, Data, Size);
    query[Size] = '\0';

    // Find a table based on the query
    char *table = lou_findTable(query);
    if (table) {
        // Get table info using a dummy key
        char *info = lou_getTableInfo(table, "dummy_key");
        if (info) {
            free(info);
        }

        free(table);
    }

    // Clean up
    lou_free();
    free(query);

    return 0;
}