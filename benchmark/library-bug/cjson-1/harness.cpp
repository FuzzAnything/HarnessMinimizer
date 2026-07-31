#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

#include "cjson/cJSON.h"
#include "cjson/cJSON_Utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for meaningful testing
    // We need enough data to create two JSON structures and perform operations
    if (size < 64) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create two diverse JSON structures for comparison
    
    // First, decide what type of comparison operation to perform
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    cJSON* json1 = nullptr;
    cJSON* json2 = nullptr;
    
    // Function to create a random JSON structure using fuzzer input
    auto create_random_json = [&fdp]() -> cJSON* {
        uint8_t json_type = fdp.ConsumeIntegral<uint8_t>() % 4;
        
        switch (json_type) {
            case 0: {
                // Create object with mixed types
                cJSON* obj = cJSON_CreateObject();
                if (!obj) return nullptr;
                
                // Add boolean
                cJSON_AddBoolToObject(obj, "bool_val", fdp.ConsumeBool());
                
                // Add number
                cJSON_AddNumberToObject(obj, "num_val", fdp.ConsumeFloatingPoint<double>());
                
                // Add string
                std::string str_val = fdp.ConsumeRandomLengthString(32);
                cJSON_AddStringToObject(obj, "str_val", str_val.c_str());
                
                // Add null
                cJSON_AddNullToObject(obj, "null_val");
                
                // Add nested array
                cJSON* nested_array = cJSON_CreateArray();
                if (nested_array) {
                    int array_len = fdp.ConsumeIntegralInRange<int>(1, 5);
                    for (int i = 0; i < array_len && fdp.remaining_bytes() > 0; i++) {
                        double val = fdp.ConsumeFloatingPoint<double>();
                        cJSON_AddItemToArray(nested_array, cJSON_CreateNumber(val));
                    }
                    cJSON_AddItemToObject(obj, "nested_array", nested_array);
                }
                
                return obj;
            }
            
            case 1: {
                // Create array with mixed types
                cJSON* array = cJSON_CreateArray();
                if (!array) return nullptr;
                
                int array_len = fdp.ConsumeIntegralInRange<int>(2, 8);
                
                for (int i = 0; i < array_len && fdp.remaining_bytes() > 0; i++) {
                    uint8_t item_type = fdp.ConsumeIntegral<uint8_t>() % 4;
                    
                    switch (item_type) {
                        case 0:
                            cJSON_AddItemToArray(array, cJSON_CreateBool(fdp.ConsumeBool()));
                            break;
                        case 1:
                            cJSON_AddItemToArray(array, cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                            break;
                        case 2: {
                            std::string str = fdp.ConsumeRandomLengthString(16);
                            cJSON_AddItemToArray(array, cJSON_CreateString(str.c_str()));
                            break;
                        }
                        case 3:
                            cJSON_AddItemToArray(array, cJSON_CreateNull());
                            break;
                    }
                }
                
                return array;
            }
            
            case 2: {
                // Create a simple string
                std::string str = fdp.ConsumeRandomLengthString(64);
                return cJSON_CreateString(str.c_str());
            }
            
            case 3: {
                // Create a number
                return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            }
            
            default:
                return nullptr;
        }
    };
    
    // Create two JSON structures
    json1 = create_random_json();
    if (!json1) return 0;
    
    json2 = create_random_json();
    if (!json2) {
        cJSON_Delete(json1);
        return 0;
    }
    
    // Step 2: Perform comparison operations with cJSON_Compare
    cJSON_bool case_sensitive = fdp.ConsumeBool();
    cJSON_bool compare_result = cJSON_Compare(json1, json2, case_sensitive);
    
    // Also try comparing each JSON with itself (should return true)
    cJSON_bool self_compare1 = cJSON_Compare(json1, json1, case_sensitive);
    cJSON_bool self_compare2 = cJSON_Compare(json2, json2, case_sensitive);
    
    // Step 3: Exercise cJSON_Utils functions
    
    // 3.1: Generate patches between the two JSON structures
    cJSON* patches = nullptr;
    if (cJSON_IsObject(json1) && cJSON_IsObject(json2)) {
        // Make copies for patch generation (since GeneratePatches modifies input)
        cJSON* json1_copy = cJSON_Duplicate(json1, 1);
        cJSON* json2_copy = cJSON_Duplicate(json2, 1);
        
        if (json1_copy && json2_copy) {
            if (case_sensitive) {
                patches = cJSONUtils_GeneratePatchesCaseSensitive(json1_copy, json2_copy);
            } else {
                patches = cJSONUtils_GeneratePatches(json1_copy, json2_copy);
            }
            
            if (patches) {
                // Try to apply patches back to verify
                if (cJSON_IsArray(patches)) {
                    // Make another copy to apply patches
                    cJSON* json1_test = cJSON_Duplicate(json1, 1);
                    if (json1_test) {
                        int apply_result;
                        if (case_sensitive) {
                            apply_result = cJSONUtils_ApplyPatchesCaseSensitive(json1_test, patches);
                        } else {
                            apply_result = cJSONUtils_ApplyPatches(json1_test, patches);
                        }
                        // Result is ignored - we're just exercising the code
                        cJSON_Delete(json1_test);
                    }
                }
                cJSON_Delete(patches);
            }
            
            cJSON_Delete(json1_copy);
            cJSON_Delete(json2_copy);
        }
    }
    
    // 3.2: Try GetPointer operations if we have objects
    if (cJSON_IsObject(json1)) {
        std::string pointer_path = fdp.ConsumeRandomLengthString(32);
        cJSON* pointer_result;
        if (case_sensitive) {
            pointer_result = cJSONUtils_GetPointerCaseSensitive(json1, pointer_path.c_str());
        } else {
            pointer_result = cJSONUtils_GetPointer(json1, pointer_path.c_str());
        }
        // Result can be NULL - that's OK
    }
    
    // 3.3: Try SortObject operations
    if (cJSON_IsObject(json1)) {
        if (case_sensitive) {
            cJSONUtils_SortObjectCaseSensitive(json1);
        } else {
            cJSONUtils_SortObject(json1);
        }
    }
    
    if (cJSON_IsObject(json2)) {
        if (case_sensitive) {
            cJSONUtils_SortObjectCaseSensitive(json2);
        } else {
            cJSONUtils_SortObject(json2);
        }
    }
    
    // 3.4: Try MergePatch operations
    if (cJSON_IsObject(json1) && cJSON_IsObject(json2)) {
        cJSON* merge_patch;
        if (case_sensitive) {
            merge_patch = cJSONUtils_GenerateMergePatchCaseSensitive(json1, json2);
        } else {
            merge_patch = cJSONUtils_GenerateMergePatch(json1, json2);
        }
        
        if (merge_patch) {
            // Apply the merge patch
            cJSON* merged_result;
            if (case_sensitive) {
                merged_result = cJSONUtils_MergePatchCaseSensitive(json1, merge_patch);
            } else {
                merged_result = cJSONUtils_MergePatch(json1, merge_patch);
            }
            // merged_result could be same as json1 or new - either way we don't need to free separately
            cJSON_Delete(merge_patch);
        }
    }
    
    // Step 4: Exercise cJSON_Minify function
    // First, create JSON strings from our structures
    char* json1_string = cJSON_PrintUnformatted(json1);
    char* json2_string = cJSON_PrintUnformatted(json2);
    
    if (json1_string) {
        // Make a copy for minification since cJSON_Minify modifies in place
        size_t len1 = strlen(json1_string);
        char* json1_copy = (char*)malloc(len1 + 1);
        if (json1_copy) {
            strcpy(json1_copy, json1_string);
            cJSON_Minify(json1_copy);
            free(json1_copy);
        }
        cJSON_free(json1_string);
    }
    
    if (json2_string) {
        size_t len2 = strlen(json2_string);
        char* json2_copy = (char*)malloc(len2 + 1);
        if (json2_copy) {
            strcpy(json2_copy, json2_string);
            cJSON_Minify(json2_copy);
            free(json2_copy);
        }
        cJSON_free(json2_string);
    }
    
    // Step 5: Try FindPointerFromObjectTo if we have nested structures
    // Create a more complex nested structure for pointer finding
    if (operation_type == 0 && fdp.remaining_bytes() > 32) {
        cJSON* complex_obj = cJSON_CreateObject();
        if (complex_obj) {
            cJSON* nested_obj = cJSON_CreateObject();
            if (nested_obj) {
                // Use fuzzer input for key and value
                std::string deep_key = fdp.ConsumeRandomLengthString(16);
                std::string deep_value = fdp.ConsumeRandomLengthString(16);
                std::string nested_key = fdp.ConsumeRandomLengthString(16);
                cJSON_AddStringToObject(nested_obj, deep_key.c_str(), deep_value.c_str());
                cJSON_AddItemToObject(complex_obj, nested_key.c_str(), nested_obj);
                
                // Find pointer from complex_obj to nested_obj
                char* pointer = cJSONUtils_FindPointerFromObjectTo(complex_obj, nested_obj);
                if (pointer) {
                    // Use the pointer with GetPointer
                    cJSON* found = cJSONUtils_GetPointer(complex_obj, pointer);
                    // found should be equal to nested_obj
                    cJSON_free(pointer);
                }
            }
            cJSON_Delete(complex_obj);
        }
    }
    
    // Step 6: Cleanup
    cJSON_Delete(json1);
    cJSON_Delete(json2);
    
    return 0;
}
