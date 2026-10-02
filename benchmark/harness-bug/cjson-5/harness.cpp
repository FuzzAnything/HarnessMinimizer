/*
 * Fuzzing harness for cJSON library - Comprehensive stress-test harness
 * Targets interaction effects by combining multiple operations from previous harnesses
 * Focus areas: 1) Chained operations (parse → modify → print → parse again)
 *             2) Mixed reference and non-reference objects
 *             3) Alternating between custom memory hooks and default allocators
 *             4) Large object graphs with deep nesting
 *             5) Repeated operations on same objects
 *             6) Testing the library's own cjson_read_fuzzer.c patterns
 * Uses FuzzedDataProvider for proper input splitting
 * This harness is designed to reveal interaction bugs not found by individual operation testing
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include "cjson/cJSON.h"
#include "cjson/cJSON_Utils.h"

// Custom memory hooks for testing allocation switching
static size_t custom_alloc_count = 0;
static size_t custom_free_count = 0;
static bool use_custom_hooks = false;

static void* custom_malloc(size_t size) {
    custom_alloc_count++;
    return malloc(size);
}

static void custom_free(void* ptr) {
    custom_free_count++;
    free(ptr);
}

// Setup custom hooks
static void setup_custom_hooks() {
    cJSON_Hooks hooks;
    hooks.malloc_fn = custom_malloc;
    hooks.free_fn = custom_free;
    cJSON_InitHooks(&hooks);
    use_custom_hooks = true;
}

// Restore default hooks
static void restore_default_hooks() {
    cJSON_Hooks hooks;
    hooks.malloc_fn = malloc;
    hooks.free_fn = free;
    cJSON_InitHooks(&hooks);
    use_custom_hooks = false;
}

// Generate deeply nested JSON with mixed reference types
static cJSON* generate_deep_nested_object(FuzzedDataProvider& fdp, int depth, bool use_refs) {
    if (depth <= 0) {
        // Create leaf node
        int leaf_type = fdp.ConsumeIntegralInRange<int>(0, 5);
        switch (leaf_type) {
            case 0: return cJSON_CreateNull();
            case 1: return cJSON_CreateTrue();
            case 2: return cJSON_CreateFalse();
            case 3: return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            case 4: {
                std::string str = fdp.ConsumeRandomLengthString(50);
                if (use_refs && fdp.ConsumeBool()) {
                    return cJSON_CreateStringReference(str.c_str());
                }
                return cJSON_CreateString(str.c_str());
            }
            default: return cJSON_CreateBool(fdp.ConsumeBool());
        }
    }
    
    if (fdp.ConsumeBool()) {
        // Create nested object
        cJSON* obj = cJSON_CreateObject();
        if (!obj) return NULL;
        
        int item_count = fdp.ConsumeIntegralInRange<int>(1, 5);
        for (int i = 0; i < item_count && fdp.remaining_bytes() > 0; i++) {
            std::string key = fdp.ConsumeRandomLengthString(20);
            cJSON* child = generate_deep_nested_object(fdp, depth - 1, use_refs);
            if (child) {
                if (use_refs && fdp.ConsumeBool()) {
                    cJSON_AddItemReferenceToObject(obj, key.c_str(), child);
                    cJSON_Delete(child); // Reference doesn't own child
                } else {
                    cJSON_AddItemToObject(obj, key.c_str(), child);
                }
            }
        }
        return obj;
    } else {
        // Create nested array
        cJSON* arr = cJSON_CreateArray();
        if (!arr) return NULL;
        
        int item_count = fdp.ConsumeIntegralInRange<int>(1, 5);
        for (int i = 0; i < item_count && fdp.remaining_bytes() > 0; i++) {
            cJSON* child = generate_deep_nested_object(fdp, depth - 1, use_refs);
            if (child) {
                if (use_refs && fdp.ConsumeBool()) {
                    cJSON_AddItemReferenceToArray(arr, child);
                    cJSON_Delete(child); // Reference doesn't own child
                } else {
                    cJSON_AddItemToArray(arr, child);
                }
            }
        }
        return arr;
    }
}

// Test chained operations: parse → modify → print → parse again
static void test_chained_operations(FuzzedDataProvider& fdp, const std::string& json_input) {
    // First parse
    cJSON* parsed1 = cJSON_Parse(json_input.c_str());
    if (!parsed1) return;
    
    // Modify the parsed JSON
    int modify_op = fdp.ConsumeIntegralInRange<int>(0, 3);
    switch (modify_op) {
        case 0: {
            // Add new items
            std::string key = fdp.ConsumeRandomLengthString(20);
            std::string value = fdp.ConsumeRandomLengthString(50);
            cJSON_AddStringToObject(parsed1, key.c_str(), value.c_str());
            break;
        }
        case 1: {
            // Replace existing items if possible
            if (cJSON_IsObject(parsed1)) {
                cJSON* child = parsed1->child;
                if (child) {
                    cJSON* new_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
                    cJSON_ReplaceItemViaPointer(parsed1, child, new_item);
                }
            }
            break;
        }
        case 2: {
            // Duplicate with recursion
            cJSON* duplicate = cJSON_Duplicate(parsed1, fdp.ConsumeBool());
            if (duplicate) {
                cJSON_Delete(duplicate);
            }
            break;
        }
        case 3: {
            // Sort object
            if (cJSON_IsObject(parsed1)) {
                cJSONUtils_SortObject(parsed1);
            }
            break;
        }
    }
    
    // Print the modified JSON
    int print_op = fdp.ConsumeIntegralInRange<int>(0, 2);
    char* printed = NULL;
    switch (print_op) {
        case 0:
            printed = cJSON_Print(parsed1);
            break;
        case 1:
            printed = cJSON_PrintUnformatted(parsed1);
            break;
        case 2: {
            int prebuffer = fdp.ConsumeIntegralInRange<int>(1, 4096);
            printed = cJSON_PrintBuffered(parsed1, prebuffer, fdp.ConsumeBool());
            break;
        }
    }
    
    // Parse the printed output again (chained parse)
    if (printed) {
        cJSON* parsed2 = cJSON_Parse(printed);
        if (parsed2) {
            // Compare the two parsed versions
            cJSON_bool are_equal = cJSON_Compare(parsed1, parsed2, fdp.ConsumeBool());
            (void)are_equal; // Use to avoid unused warning
            
            // Test repeated operations on same object
            for (int i = 0; i < 3 && fdp.remaining_bytes() > 0; i++) {
                // Repeatedly add/remove items
                std::string temp_key = fdp.ConsumeRandomLengthString(10);
                cJSON_AddNumberToObject(parsed2, temp_key.c_str(), fdp.ConsumeFloatingPoint<double>());
                
                if (cJSON_IsObject(parsed2)) {
                    cJSON_DetachItemFromObject(parsed2, temp_key.c_str());
                }
            }
            
            cJSON_Delete(parsed2);
        }
        free(printed);
    }
    
    cJSON_Delete(parsed1);
}

// Test cjson_read_fuzzer.c patterns
static void test_read_fuzzer_patterns(FuzzedDataProvider& fdp, const uint8_t* data, size_t size) {
    // Mimic the pattern from cjson_read_fuzzer.c
    if (size < 5) return; // Need at least 4 flags + 1 byte of JSON
    
    // Check first 4 bytes for flags (simplified version)
    bool minify = (data[0] & 0x01) != 0;
    bool require_termination = (data[1] & 0x01) != 0;
    bool formatted = (data[2] & 0x01) != 0;
    bool buffered = (data[3] & 0x01) != 0;
    
    // Use remaining data as JSON input
    const char* json_input = reinterpret_cast<const char*>(data + 4);
    size_t json_size = size - 4;
    
    if (json_size == 0) return;
    
    // Parse with options
    cJSON* json = cJSON_ParseWithOpts(json_input, NULL, require_termination ? 1 : 0);
    if (!json) return;
    
    // Print with different options
    char* printed_json = NULL;
    if (buffered) {
        printed_json = cJSON_PrintBuffered(json, 1, formatted ? 1 : 0);
    } else {
        if (formatted) {
            printed_json = cJSON_Print(json);
        } else {
            printed_json = cJSON_PrintUnformatted(json);
        }
    }
    
    if (printed_json) {
        free(printed_json);
    }
    
    // Minify if requested
    if (minify && json_size > 0) {
        // Need writable copy for minify
        char* writable_json = static_cast<char*>(malloc(json_size + 1));
        if (writable_json) {
            memcpy(writable_json, json_input, json_size);
            writable_json[json_size] = '\0';
            cJSON_Minify(writable_json);
            free(writable_json);
        }
    }
    
    cJSON_Delete(json);
}

// Test mixed reference and non-reference objects
static void test_mixed_references(FuzzedDataProvider& fdp) {
    // Create a complex object with mixed reference types
    cJSON* root = cJSON_CreateObject();
    if (!root) return;
    
    // Add regular items
    cJSON_AddNumberToObject(root, "regular_number", fdp.ConsumeFloatingPoint<double>());
    cJSON_AddStringToObject(root, "regular_string", fdp.ConsumeRandomLengthString(50).c_str());
    
    // Add reference items
    std::string ref_string = fdp.ConsumeRandomLengthString(50);
    cJSON* string_ref = cJSON_CreateStringReference(ref_string.c_str());
    cJSON_AddItemToObject(root, "string_reference", string_ref);
    
    // Create array with mixed references
    cJSON* mixed_array = cJSON_CreateArray();
    if (mixed_array) {
        // Add regular items
        cJSON_AddItemToArray(mixed_array, cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        cJSON_AddItemToArray(mixed_array, cJSON_CreateString(fdp.ConsumeRandomLengthString(30).c_str()));
        
        // Add reference to existing item
        cJSON_AddItemReferenceToArray(mixed_array, string_ref);
        
        // Add array to root
        cJSON_AddItemToObject(root, "mixed_array", mixed_array);
    }
    
    // Create object reference
    cJSON* obj_ref = cJSON_CreateObjectReference(root);
    if (obj_ref) {
        cJSON_AddItemToObject(root, "self_reference", obj_ref);
    }
    
    // Test operations on mixed structure - print and parse
    char* printed = cJSON_Print(root);
    if (printed) {
        // Try to parse the printed output
        cJSON* reparsed = cJSON_Parse(printed);
        if (reparsed) {
            cJSON_Delete(reparsed);
        }
        free(printed);
    }
    
    cJSON_Delete(root);
}

// Test alternating memory hooks
static void test_memory_hook_switching(FuzzedDataProvider& fdp, const std::string& json_input) {
    // Start with default hooks
    restore_default_hooks();
    
    // Parse with default hooks
    cJSON* json1 = cJSON_Parse(json_input.c_str());
    if (!json1) return;
    
    // Switch to custom hooks
    setup_custom_hooks();
    
    // Create new object with custom hooks
    cJSON* json2 = cJSON_CreateObject();
    if (json2) {
        std::string key = fdp.ConsumeRandomLengthString(20);
        std::string value = fdp.ConsumeRandomLengthString(50);
        cJSON_AddStringToObject(json2, key.c_str(), value.c_str());
        
        // Print with custom hooks
        char* printed = cJSON_Print(json2);
        if (printed) {
            free(printed);
        }
        
        cJSON_Delete(json2);
    }
    
    // Switch back to default hooks while first object still exists
    restore_default_hooks();
    
    // Modify first object (still allocated with default hooks)
    cJSON_AddNumberToObject(json1, "added_after_switch", fdp.ConsumeFloatingPoint<double>());
    
    // Print with default hooks
    char* printed1 = cJSON_Print(json1);
    if (printed1) {
        free(printed1);
    }
    
    // Switch to custom hooks again
    setup_custom_hooks();
    
    // Duplicate object (should use custom hooks for allocation)
    cJSON* duplicate = cJSON_Duplicate(json1, fdp.ConsumeBool());
    if (duplicate) {
        cJSON_Delete(duplicate);
    }
    
    cJSON_Delete(json1);
    
    // Restore defaults for cleanup
    restore_default_hooks();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive testing
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters
    int test_phase = fdp.ConsumeIntegralInRange<int>(0, 5);
    bool use_refs_in_generation = fdp.ConsumeBool();
    bool alternate_hooks = fdp.ConsumeBool();
    int nesting_depth = fdp.ConsumeIntegralInRange<int>(1, 10);
    
    // Consume JSON input data
    std::string json_input = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
    
    // Execute different test phases based on configuration
    switch (test_phase) {
        case 0:
            // Test 1: Chained operations
            test_chained_operations(fdp, json_input);
            break;
            
        case 1:
            // Test 2: Large object graphs with deep nesting
            if (fdp.remaining_bytes() > 100) {
                cJSON* deep_obj = generate_deep_nested_object(fdp, nesting_depth, use_refs_in_generation);
                if (deep_obj) {
                    // Perform operations on deep object
                    char* printed = cJSON_Print(deep_obj);
                    if (printed) {
                        // Try to parse the printed deep object
                        cJSON* reparsed = cJSON_Parse(printed);
                        if (reparsed) {
                            cJSON_Delete(reparsed);
                        }
                        free(printed);
                    }
                    cJSON_Delete(deep_obj);
                }
            }
            break;
            
        case 2:
            // Test 3: Mixed reference and non-reference objects
            test_mixed_references(fdp);
            break;
            
        case 3:
            // Test 4: Alternating memory hooks
            if (alternate_hooks) {
                test_memory_hook_switching(fdp, json_input);
            }
            break;
            
        case 4:
            // Test 5: cjson_read_fuzzer.c patterns
            test_read_fuzzer_patterns(fdp, data, size);
            break;
            
        case 5:
            // Test 6: Combined stress test - all operations
            // Generate deep object
            cJSON* stress_obj = generate_deep_nested_object(fdp, nesting_depth / 2, true);
            if (stress_obj) {
                // Test with alternating hooks
                if (alternate_hooks) {
                    setup_custom_hooks();
                }
                
                // Perform chained operations
                char* printed = cJSON_Print(stress_obj);
                if (printed) {
                    std::string printed_str(printed);
                    free(printed);
                    
                    // Parse printed output
                    cJSON* reparsed = cJSON_Parse(printed_str.c_str());
                    if (reparsed) {
                        // Modify and re-print
                        cJSON_AddNumberToObject(reparsed, "stress_test_key", fdp.ConsumeFloatingPoint<double>());
                        
                        char* reprinted = cJSON_PrintUnformatted(reparsed);
                        if (reprinted) {
                            free(reprinted);
                        }
                        
                        cJSON_Delete(reparsed);
                    }
                }
                
                if (alternate_hooks) {
                    restore_default_hooks();
                }
                
                cJSON_Delete(stress_obj);
            }
            break;
    }
    
    // Final cleanup: ensure default hooks are restored
    restore_default_hooks();
    
    return 0;
}
