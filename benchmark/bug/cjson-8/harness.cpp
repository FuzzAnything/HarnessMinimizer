// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_DeleteItemFromArray at cJSON.c:2304:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateArray at cJSON.c:2598:23 in cJSON.h
// cJSON_GetArraySize at cJSON.c:1899:19 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateStringArray at cJSON.c:2741:23 in cJSON.h
// cJSON_GetArraySize at cJSON.c:1899:19 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_DeleteItemFromArray at cJSON.c:2304:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateIntArray at cJSON.c:2621:23 in cJSON.h
// cJSON_GetArraySize at cJSON.c:1899:19 in cJSON.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cjson/cJSON.h"

static int parse_byte_as_count(const uint8_t byte) {
    return (int)(byte % 10);  // Limit to reasonable array sizes
}

static int parse_byte_as_index(const uint8_t byte, int array_size) {
    if (array_size <= 0) return 0;
    return (int)(byte % array_size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;  // Need at least some data for testing

    // Test cJSON_CreateArray
    cJSON *empty_array = cJSON_CreateArray();
    if (empty_array) {
        cJSON_GetArraySize(empty_array);
        cJSON_Delete(empty_array);
    }

    // Test cJSON_CreateStringArray
    int string_count = parse_byte_as_count(Data[0]);
    if (string_count > 0 && Size > (size_t)string_count) {
        const char **strings = (const char **)malloc(string_count * sizeof(const char *));
        if (strings) {
            size_t data_index = 1;
            for (int i = 0; i < string_count && data_index < Size; i++) {
                // Create null-terminated strings from fuzzer data
                size_t str_len = (size_t)(Data[data_index] % 16) + 1;  // 1-16 bytes
                if (data_index + str_len >= Size) break;
                
                char *str = (char *)malloc(str_len + 1);
                if (str) {
                    memcpy(str, Data + data_index, str_len);
                    str[str_len] = '\0';
                    strings[i] = str;
                    data_index += str_len;
                } else {
                    strings[i] = "";
                }
            }
            
            cJSON *string_array = cJSON_CreateStringArray(strings, string_count);
            if (string_array) {
                // Test cJSON_GetArraySize
                int array_size = cJSON_GetArraySize(string_array);
                
                // Test cJSON_GetArrayItem with valid and invalid indices
                if (array_size > 0) {
                    int valid_index = parse_byte_as_index(Data[0], array_size);
                    cJSON_GetArrayItem(string_array, valid_index);
                    cJSON_GetArrayItem(string_array, -1);  // Invalid index
                    cJSON_GetArrayItem(string_array, array_size);  // Out of bounds
                    
                    // Test cJSON_DeleteItemFromArray
                    if (array_size > 1) {
                        int delete_index = parse_byte_as_index(Data[1], array_size);
                        cJSON_DeleteItemFromArray(string_array, delete_index);
                    }
                }
                
                cJSON_Delete(string_array);
            }
            
            // Free allocated strings
            for (int i = 0; i < string_count; i++) {
                if (strings[i] && strings[i][0] != '\0') {
                    free((void *)strings[i]);
                }
            }
            free(strings);
        }
    }

    // Test cJSON_CreateIntArray
    int int_count = parse_byte_as_count(Data[Size > 1 ? 1 : 0]);
    if (int_count > 0 && Size > (size_t)(int_count * sizeof(int))) {
        int *numbers = (int *)malloc(int_count * sizeof(int));
        if (numbers) {
            size_t data_index = 2;
            for (int i = 0; i < int_count && data_index + sizeof(int) <= Size; i++) {
                memcpy(&numbers[i], Data + data_index, sizeof(int));
                data_index += sizeof(int);
            }
            
            cJSON *int_array = cJSON_CreateIntArray(numbers, int_count);
            if (int_array) {
                // Test cJSON_GetArraySize
                int array_size = cJSON_GetArraySize(int_array);
                
                // Test cJSON_GetArrayItem with valid and invalid indices
                if (array_size > 0) {
                    int valid_index = parse_byte_as_index(Data[0], array_size);
                    cJSON_GetArrayItem(int_array, valid_index);
                    cJSON_GetArrayItem(int_array, -1);  // Invalid index
                    cJSON_GetArrayItem(int_array, array_size);  // Out of bounds
                    
                    // Test cJSON_DeleteItemFromArray
                    if (array_size > 1) {
                        int delete_index = parse_byte_as_index(Data[1], array_size);
                        cJSON_DeleteItemFromArray(int_array, delete_index);
                    }
                }
                
                cJSON_Delete(int_array);
            }
            free(numbers);
        }
    }

    return 0;
}
