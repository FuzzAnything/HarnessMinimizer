/*
 * harness_009.cpp - cJSON minification and replacement operations harness
 * 
 * This harness targets JSON minification and object replacement functions:
 * Primary target: cJSON_Minify (22 undiscovered branches)
 * Secondary targets: 
 * - cJSON_ReplaceItemInObjectCaseSensitive (9 undiscovered branches)
 * - cJSON_ReplaceItemInObject (9 undiscovered branches)
 * - cJSON_IsFalse (2 undiscovered branches)
 * - cJSON_IsArray (2 undiscovered branches)
 * - cJSON_IsBool (2 undiscovered branches)
 * - cJSON_IsInvalid (2 undiscovered branches)
 * - cJSON_IsTrue (2 undiscovered branches)
 * - cJSON_IsNull (2 undiscovered branches)
 * 
 * Following the invocation sequence:
 * 1. Parse input JSON strings using cJSON_Parse
 * 2. Create JSON objects with various structures using CreateObject/CreateArray
 * 3. Test type checking functions on parsed objects
 * 4. Perform object replacement operations
 * 5. Print JSON to string buffers using cJSON_PrintBuffered
 * 6. Apply cJSON_Minify on the printed strings
 * 7. Validate minified output
 * 8. Clean up with cJSON_Delete
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "cjson/cJSON.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 32) {
        return 0;  // Need minimum input for meaningful testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Parse input JSON strings
    // Consume a JSON string from fuzzed data
    std::string json_input = fdp.ConsumeRandomLengthString(512);
    cJSON* parsed_json = cJSON_Parse(json_input.c_str());
    
    // Step 2: Create JSON objects with various structures
    cJSON* root_object = cJSON_CreateObject();
    cJSON* root_array = cJSON_CreateArray();
    
    if (root_object == nullptr || root_array == nullptr) {
        if (parsed_json != nullptr) cJSON_Delete(parsed_json);
        if (root_object != nullptr) cJSON_Delete(root_object);
        if (root_array != nullptr) cJSON_Delete(root_array);
        return 0;
    }
    
    // Create various JSON items to add to objects/arrays
    // Create numbers
    for (int i = 0; i < 3 && fdp.remaining_bytes() > 8; i++) {
        double num_value = fdp.ConsumeFloatingPoint<double>();
        cJSON* num_item = cJSON_CreateNumber(num_value);
        if (num_item != nullptr) {
            char key[32];
            snprintf(key, sizeof(key), "num_%d", i);
            cJSON_AddItemToObject(root_object, key, num_item);
            cJSON_AddItemToArray(root_array, num_item);
        }
    }
    
    // Create strings
    for (int i = 0; i < 3 && fdp.remaining_bytes() > 16; i++) {
        std::string str_value = fdp.ConsumeRandomLengthString(128);
        cJSON* str_item = cJSON_CreateString(str_value.c_str());
        if (str_item != nullptr) {
            char key[32];
            snprintf(key, sizeof(key), "str_%d", i);
            cJSON_AddItemToObject(root_object, key, str_item);
            cJSON_AddItemToArray(root_array, str_item);
        }
    }
    
    // Create booleans
    cJSON* true_item = cJSON_CreateTrue();
    cJSON* false_item = cJSON_CreateFalse();
    if (true_item != nullptr) {
        cJSON_AddItemToObject(root_object, "bool_true", true_item);
        cJSON_AddItemToArray(root_array, true_item);
    }
    if (false_item != nullptr) {
        cJSON_AddItemToObject(root_object, "bool_false", false_item);
        cJSON_AddItemToArray(root_array, false_item);
    }
    
    // Create null
    cJSON* null_item = cJSON_CreateNull();
    if (null_item != nullptr) {
        cJSON_AddItemToObject(root_object, "null_item", null_item);
        cJSON_AddItemToArray(root_array, null_item);
    }
    
    // Step 3: Test type checking functions on parsed objects
    if (parsed_json != nullptr) {
        // Test various type checking functions
        (void)cJSON_IsInvalid(parsed_json);
        (void)cJSON_IsFalse(parsed_json);
        (void)cJSON_IsTrue(parsed_json);
        (void)cJSON_IsBool(parsed_json);
        (void)cJSON_IsNull(parsed_json);
        (void)cJSON_IsArray(parsed_json);
        (void)cJSON_IsObject(parsed_json);
        (void)cJSON_IsString(parsed_json);
        (void)cJSON_IsNumber(parsed_json);
    }
    
    // Also test on created items
    if (true_item != nullptr) {
        (void)cJSON_IsTrue(true_item);
        (void)cJSON_IsBool(true_item);
    }
    if (false_item != nullptr) {
        (void)cJSON_IsFalse(false_item);
        (void)cJSON_IsBool(false_item);
    }
    if (null_item != nullptr) {
        (void)cJSON_IsNull(null_item);
    }
    
    // Step 4: Perform object replacement operations
    // Create replacement items
    std::string replacement_str = fdp.ConsumeRandomLengthString(64);
    cJSON* replacement_string = cJSON_CreateString(replacement_str.c_str());
    double replacement_num = fdp.ConsumeFloatingPoint<double>();
    cJSON* replacement_number = cJSON_CreateNumber(replacement_num);
    
    // Perform case-sensitive replacement
    if (replacement_string != nullptr) {
        cJSON_ReplaceItemInObjectCaseSensitive(root_object, "str_0", replacement_string);
    }
    
    // Perform case-insensitive replacement
    if (replacement_number != nullptr) {
        cJSON_ReplaceItemInObject(root_object, "num_0", replacement_number);
    }
    
    // Try to replace non-existent keys (should handle gracefully)
    cJSON* dummy_item = cJSON_CreateString("dummy");
    if (dummy_item != nullptr) {
        cJSON_ReplaceItemInObjectCaseSensitive(root_object, "non_existent_key", dummy_item);
        cJSON_ReplaceItemInObject(root_object, "another_non_existent", dummy_item);
        cJSON_Delete(dummy_item);
    }
    
    // Step 5: Print JSON to string buffers
    char* printed_object = cJSON_PrintBuffered(root_object, 1024, 1); // Formatted
    char* printed_array = cJSON_PrintBuffered(root_array, 1024, 0);   // Unformatted
    
    // Step 6: Apply cJSON_Minify on the printed strings
    if (printed_object != nullptr) {
        // Create a writable copy since cJSON_Minify modifies the string in place
        size_t obj_len = strlen(printed_object);
        char* minifiable_object = (char*)malloc(obj_len + 1);
        if (minifiable_object != nullptr) {
            strcpy(minifiable_object, printed_object);
            cJSON_Minify(minifiable_object);
            free(minifiable_object);
        }
    }
    
    if (printed_array != nullptr) {
        // Create a writable copy for minification
        size_t arr_len = strlen(printed_array);
        char* minifiable_array = (char*)malloc(arr_len + 1);
        if (minifiable_array != nullptr) {
            strcpy(minifiable_array, printed_array);
            cJSON_Minify(minifiable_array);
            free(minifiable_array);
        }
    }
    
    // Also test minification on fuzzed JSON input string
    if (!json_input.empty()) {
        // Create writable copy of input JSON
        char* minifiable_input = (char*)malloc(json_input.size() + 1);
        if (minifiable_input != nullptr) {
            strcpy(minifiable_input, json_input.c_str());
            cJSON_Minify(minifiable_input);
            free(minifiable_input);
        }
    }
    
    // Test edge cases for minification
    // Test with empty string
    char empty_str[] = "";
    cJSON_Minify(empty_str);
    
    // Test with string containing only whitespace
    char whitespace_str[] = "   \t\n\r  ";
    cJSON_Minify(whitespace_str);
    
    // Test with string containing comments
    char comment_str[] = "{\"key\": \"value\" // comment\n}";
    cJSON_Minify(comment_str);
    
    // Step 7: Validate minified output (basic validation)
    // The minification function doesn't return a value, so we just ensure
    // it doesn't crash and handles various inputs
    
    // Step 8: Clean up
    if (parsed_json != nullptr) {
        cJSON_Delete(parsed_json);
    }
    if (root_object != nullptr) {
        cJSON_Delete(root_object);
    }
    if (root_array != nullptr) {
        cJSON_Delete(root_array);
    }
    if (printed_object != nullptr) {
        free(printed_object);
    }
    if (printed_array != nullptr) {
        free(printed_array);
    }
    
    return 0;
}
