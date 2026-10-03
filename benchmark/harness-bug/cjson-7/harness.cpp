// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_AddItemToArray at cJSON.c:2061:26 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_Print at cJSON.c:1307:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Minify at cJSON.c:2924:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddStringToObject at cJSON.c:2210:22 in cJSON.h
// cJSON_AddNumberToObject at cJSON.c:2198:22 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddBoolToObject at cJSON.c:2186:22 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_PrintUnformatted at cJSON.c:1312:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddStringToObject at cJSON.c:2210:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_PrintPreallocated at cJSON.c:1348:26 in cJSON.h
// cJSON_PrintPreallocated at cJSON.c:1348:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateArray at cJSON.c:2598:23 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_AddItemToArray at cJSON.c:2061:26 in cJSON.h
// cJSON_PrintBuffered at cJSON.c:1317:22 in cJSON.h
// cJSON_PrintBuffered at cJSON.c:1317:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateIntArray at cJSON.c:2621:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_CreateArray at cJSON.c:2598:23 in cJSON.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "cjson/cJSON.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void test_cJSON_PrintPreallocated(const uint8_t *data, size_t size) {
    if (size < 10) return;
    
    // Create a simple JSON object from fuzzer data
    cJSON *root = cJSON_CreateObject();
    if (!root) return;
    
    // Add some values using fuzzer data
    char key[32];
    snprintf(key, sizeof(key), "key_%zu", size % 20);
    cJSON_AddStringToObject(root, key, (const char*)data);
    
    // Create buffer for preallocated printing
    int buffer_size = (size % 1024) + 100; // Ensure minimum size
    char *buffer = (char*)malloc(buffer_size);
    if (!buffer) {
        cJSON_Delete(root);
        return;
    }
    
    // Test with both formatted and unformatted output
    cJSON_PrintPreallocated(root, buffer, buffer_size, 0);
    cJSON_PrintPreallocated(root, buffer, buffer_size, 1);
    
    free(buffer);
    cJSON_Delete(root);
}

static void test_cJSON_PrintBuffered(const uint8_t *data, size_t size) {
    if (size < 5) return;
    
    // Create array from fuzzer data
    cJSON *array = cJSON_CreateArray();
    if (!array) return;
    
    // Add some items to the array
    for (size_t i = 0; i < (size % 10) && i < size; i++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(data[i]));
    }
    
    // Test with different prebuffer sizes and formats
    int prebuffer = (size % 512) + 10;
    char *result1 = cJSON_PrintBuffered(array, prebuffer, 0);
    if (result1) free(result1);
    
    char *result2 = cJSON_PrintBuffered(array, prebuffer, 1);
    if (result2) free(result2);
    
    cJSON_Delete(array);
}

static void test_cJSON_CreateIntArray(const uint8_t *data, size_t size) {
    if (size < 4) return;
    
    // Create integer array from fuzzer data
    size_t count = size % 100; // Limit to reasonable size
    if (count > size / sizeof(int)) {
        count = size / sizeof(int);
    }
    
    if (count == 0) return;
    
    int *numbers = (int*)malloc(count * sizeof(int));
    if (!numbers) return;
    
    // Copy fuzzer data as integers
    for (size_t i = 0; i < count; i++) {
        numbers[i] = (int)data[i % size];
    }
    
    cJSON *array = cJSON_CreateIntArray(numbers, (int)count);
    if (array) {
        cJSON_Delete(array);
    }
    
    free(numbers);
}

static void test_cJSON_Print(const uint8_t *data, size_t size) {
    if (size < 5) return;
    
    // Create a nested structure
    cJSON *root = cJSON_CreateObject();
    if (!root) return;
    
    cJSON *array = cJSON_CreateArray();
    if (array) {
        for (size_t i = 0; i < (size % 5) && i < size; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(data[i]));
        }
        cJSON_AddItemToObject(root, "fuzz_array", array);
    }
    
    // Test regular print
    char *printed = cJSON_Print(root);
    if (printed) free(printed);
    
    cJSON_Delete(root);
}

static void test_cJSON_Minify(const uint8_t *data, size_t size) {
    if (size == 0) return;
    
    // Create a writable buffer for minification
    char *json_buffer = (char*)malloc(size + 1);
    if (!json_buffer) return;
    
    memcpy(json_buffer, data, size);
    json_buffer[size] = '\0';
    
    // Test minification
    cJSON_Minify(json_buffer);
    
    free(json_buffer);
}

static void test_cJSON_PrintUnformatted(const uint8_t *data, size_t size) {
    if (size < 5) return;
    
    // Create a mixed JSON object
    cJSON *root = cJSON_CreateObject();
    if (!root) return;
    
    // Add different types of values
    cJSON_AddStringToObject(root, "fuzz_string", (const char*)data);
    cJSON_AddNumberToObject(root, "fuzz_number", (double)(size % 1000));
    
    cJSON *nested = cJSON_CreateObject();
    if (nested) {
        cJSON_AddBoolToObject(nested, "fuzz_bool", size % 2);
        cJSON_AddItemToObject(root, "nested", nested);
    }
    
    // Test unformatted print
    char *result = cJSON_PrintUnformatted(root);
    if (result) free(result);
    
    cJSON_Delete(root);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Test all target functions with the fuzzer input
    
    test_cJSON_PrintPreallocated(Data, Size);
    test_cJSON_PrintBuffered(Data, Size);
    test_cJSON_CreateIntArray(Data, Size);
    test_cJSON_Print(Data, Size);
    test_cJSON_Minify(Data, Size);
    test_cJSON_PrintUnformatted(Data, Size);
    
    return 0;
}
