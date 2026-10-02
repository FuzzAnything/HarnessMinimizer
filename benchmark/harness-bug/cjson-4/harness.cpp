/*
 * Harness 020: Structural comparison operations targeting cJSON_Compare
 * 
 * Focus: Deeply nested JSON structure comparisons with property ordering variations,
 * array element ordering, case-sensitive/insensitive string comparison, and
 * floating-point precision edge cases.
 * 
 * Blocked branches to target in cJSON_Compare: 73/76 branches
 * 
 * Semantic diversity from existing harnesses:
 * - harness_000: Basic parsing and creation (doesn't target comparisons)
 * - harness_019: Edge case comparisons (NULL, type mismatches, simple structures)
 * - This harness: Complex structural comparisons with ordering variations
 * 
 * Specific test scenarios:
 * 1. Compare deeply nested objects with property ordering variations
 * 2. Compare arrays with different element ordering
 * 3. Test case-sensitive vs case-insensitive string comparison
 * 4. Compare floating-point numbers near precision limits
 * 5. Edge cases: NULL inputs, invalid JSON types
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>
#include <map>

#include "cjson/cJSON.h"
// Helper function to shuffle vector using fuzzed data for randomness
template<typename T>
static void shuffle_with_fdp(std::vector<T>& vec, FuzzedDataProvider& fdp) {
    if (vec.size() <= 1) return;
    
    // Fisher-Yates shuffle using fuzzed random indices
    for (size_t i = vec.size() - 1; i > 0; i--) {
        size_t j = fdp.ConsumeIntegralInRange<size_t>(0, i);
        std::swap(vec[i], vec[j]);
    }
}

// Helper function to create deeply nested object with configurable depth
static cJSON* create_deep_nested_object(FuzzedDataProvider& fdp, int max_depth, bool vary_property_order) {
    if (max_depth <= 0) {
        // Create leaf node
        uint8_t leaf_type = fdp.ConsumeIntegral<uint8_t>() % 4;
        switch (leaf_type) {
            case 0:
                return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            case 1:
                return cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str());
            case 2:
                return cJSON_CreateBool(fdp.ConsumeBool());
            default:
                return cJSON_CreateNull();
        }
    }
    
    cJSON* obj = cJSON_CreateObject();
    if (!obj) return NULL;
    
    // Create multiple properties at this level
    int num_properties = fdp.ConsumeIntegralInRange<int>(1, 5);
    std::vector<std::string> property_names;
    
    for (int i = 0; i < num_properties; i++) {
        property_names.push_back(fdp.ConsumeRandomLengthString(16));
    }
    
    // Optionally shuffle property order for second object
    std::vector<std::string> shuffled_names = property_names;
    if (vary_property_order) {
        shuffle_with_fdp(shuffled_names, fdp);
    }
    
    // Add properties to object
    for (size_t i = 0; i < property_names.size(); i++) {
        const std::string& prop_name = vary_property_order ? shuffled_names[i] : property_names[i];
        cJSON* value = create_deep_nested_object(fdp, max_depth - 1, vary_property_order);
        if (value) {
            cJSON_AddItemToObject(obj, prop_name.c_str(), value);
        }
    }

    
    return obj;
}

// Helper to create array with configurable element ordering
static cJSON* create_array_with_ordering(FuzzedDataProvider& fdp, int size, bool vary_element_order) {
    cJSON* arr = cJSON_CreateArray();
    if (!arr) return NULL;
    
    std::vector<cJSON*> elements;
    
    for (int i = 0; i < size; i++) {
        uint8_t elem_type = fdp.ConsumeIntegral<uint8_t>() % 5;
        cJSON* elem = NULL;
        
        switch (elem_type) {
            case 0:
                elem = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
                break;
            case 1:
                elem = cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str());
                break;
            case 2:
                elem = cJSON_CreateBool(fdp.ConsumeBool());
                break;
            case 3:
                elem = cJSON_CreateNull();
                break;
            case 4: {
                // Nested array
                int nested_size = fdp.ConsumeIntegralInRange<int>(1, 3);
                elem = create_array_with_ordering(fdp, nested_size, vary_element_order);
                break;
            }
        }
        
        if (elem) {
            elements.push_back(elem);
        }
    }
    
    // Optionally shuffle element order
    if (vary_element_order && elements.size() > 1) {
        shuffle_with_fdp(elements, fdp);
    }
    
    // Add elements to array
    for (cJSON* elem : elements) {
        cJSON_AddItemToArray(arr, elem);
    }
    
    return arr;
}

// Helper to compare floating-point numbers with precision variations
static void test_floating_point_comparisons(FuzzedDataProvider& fdp, bool case_sensitive) {
    // Test various floating-point edge cases
    std::vector<double> test_values;
    
    // Generate edge case values
    test_values.push_back(0.0);
    test_values.push_back(-0.0);
    test_values.push_back(1.0);
    test_values.push_back(-1.0);
    
    // Generate fuzzed values near precision limits
    for (int i = 0; i < 5; i++) {
        // Very small numbers near double precision limits
        double tiny = fdp.ConsumeFloatingPointInRange<double>(1e-308, 1e-300);
        test_values.push_back(tiny);
        test_values.push_back(-tiny);
        
        // Very large numbers
        double huge = fdp.ConsumeFloatingPointInRange<double>(1e300, 1e308);
        test_values.push_back(huge);
        test_values.push_back(-huge);
        
        // Numbers with many decimal places
        double precise = fdp.ConsumeFloatingPointInRange<double>(0.000001, 0.999999);
        test_values.push_back(precise);
        
        // Numbers that might cause rounding issues
        double rounding = fdp.ConsumeFloatingPointInRange<double>(0.1, 0.9);
        for (int j = 0; j < 10; j++) {
            rounding += 0.1;
        }
        test_values.push_back(rounding);
    }
    
    // Compare all pairs of test values
    for (size_t i = 0; i < test_values.size(); i++) {
        for (size_t j = 0; j < test_values.size(); j++) {
            cJSON* num1 = cJSON_CreateNumber(test_values[i]);
            cJSON* num2 = cJSON_CreateNumber(test_values[j]);
            
            if (num1 && num2) {
                cJSON_Compare(num1, num2, case_sensitive);
            }
            
            if (num1) cJSON_Delete(num1);
            if (num2) cJSON_Delete(num2);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 64) {
        return 0;  // Need sufficient data for complex structures
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters
    uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 6;
    bool case_sensitive = fdp.ConsumeBool();
    bool vary_property_order = fdp.ConsumeBool();
    bool vary_element_order = fdp.ConsumeBool();
    
    cJSON *item1 = NULL;
    cJSON *item2 = NULL;
    
    switch (test_scenario) {
        case 0: {
            // Scenario 1: Deeply nested objects with property ordering variations
            int depth = fdp.ConsumeIntegralInRange<int>(1, 6);
            
            // Create two objects with same structure but potentially different property order
            item1 = create_deep_nested_object(fdp, depth, false);
            item2 = create_deep_nested_object(fdp, depth, vary_property_order);
            
            if (item1 && item2) {
                cJSON_Compare(item1, item2, case_sensitive);
            }
            
            // Also test with intentionally different structures
            cJSON* diff_item = create_deep_nested_object(fdp, depth - 1, false);
            if (item1 && diff_item) {
                cJSON_Compare(item1, diff_item, case_sensitive);
            }
            
            if (diff_item) cJSON_Delete(diff_item);
            break;
        }
        
        case 1: {
            // Scenario 2: Arrays with different element ordering
            int array_size = fdp.ConsumeIntegralInRange<int>(2, 8);
            
            // Create two arrays with same elements but potentially different order
            item1 = create_array_with_ordering(fdp, array_size, false);
            item2 = create_array_with_ordering(fdp, array_size, vary_element_order);
            
            if (item1 && item2) {
                cJSON_Compare(item1, item2, case_sensitive);
            }
            
            // Test with arrays of different sizes
            cJSON* smaller_array = create_array_with_ordering(fdp, array_size - 1, false);
            if (item1 && smaller_array) {
                cJSON_Compare(item1, smaller_array, case_sensitive);
            }
            
            if (smaller_array) cJSON_Delete(smaller_array);
            break;
        }
        
        case 2: {
            // Scenario 3: Case-sensitive vs case-insensitive string comparison
            std::string base_str = fdp.ConsumeRandomLengthString(32);
            if (base_str.empty()) {
                base_str = "TestString";
            }
            
            // Create variations of the string
            std::string lower_str = base_str;
            std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
            
            std::string upper_str = base_str;
            std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(), ::toupper);
            
            // Create mixed case version
            std::string mixed_str = base_str;
            for (size_t i = 0; i < mixed_str.length(); i++) {
                if (i % 2 == 0) {
                    mixed_str[i] = std::toupper(mixed_str[i]);
                } else {
                    mixed_str[i] = std::tolower(mixed_str[i]);
                }
            }
            
            // Test all combinations with both case_sensitive settings
            std::vector<cJSON*> string_items;
            string_items.push_back(cJSON_CreateString(base_str.c_str()));
            string_items.push_back(cJSON_CreateString(lower_str.c_str()));
            string_items.push_back(cJSON_CreateString(upper_str.c_str()));
            string_items.push_back(cJSON_CreateString(mixed_str.c_str()));
            
            for (size_t i = 0; i < string_items.size(); i++) {
                for (size_t j = 0; j < string_items.size(); j++) {
                    if (string_items[i] && string_items[j]) {
                        // Test both case-sensitive and case-insensitive
                        cJSON_Compare(string_items[i], string_items[j], true);   // case-sensitive
                        cJSON_Compare(string_items[i], string_items[j], false);  // case-insensitive
                    }
                }
            }
            
            // Clean up
            for (cJSON* str_item : string_items) {
                if (str_item) cJSON_Delete(str_item);
            }
            break;
        }
        
        case 3: {
            // Scenario 4: Floating-point numbers near precision limits
            test_floating_point_comparisons(fdp, case_sensitive);
            break;
        }
        
        case 4: {
            // Scenario 5: NULL inputs and edge cases
            // Test various NULL combinations
            cJSON_Compare(NULL, NULL, case_sensitive);
            
            // Create valid objects and compare with NULL
            item1 = cJSON_CreateObject();
            if (item1) {
                cJSON_Compare(item1, NULL, case_sensitive);
                cJSON_Compare(NULL, item1, case_sensitive);
                
                // Add some content and test again
                cJSON_AddStringToObject(item1, "test", fdp.ConsumeRandomLengthString(16).c_str());
                cJSON_Compare(item1, NULL, case_sensitive);
            }
            
            // Test with potentially invalid types
            if (fdp.ConsumeBool()) {
                cJSON* potentially_invalid = cJSON_CreateNumber(42.0);
                if (potentially_invalid && fdp.ConsumeBool()) {
                    // Try to create edge case by manipulating type field
                    // (Testing how cJSON_Compare handles unexpected type bits)
                    potentially_invalid->type = fdp.ConsumeIntegral<uint8_t>();
                    cJSON_Compare(potentially_invalid, potentially_invalid, case_sensitive);
                }
                if (potentially_invalid) cJSON_Delete(potentially_invalid);
            }
            break;
        }
        
        case 5: {
            // Scenario 6: Mixed complex structures - combination of all above
            std::string json_input = fdp.ConsumeRemainingBytesAsString();
            if (!json_input.empty()) {
                // Parse JSON and create variations
                item1 = cJSON_Parse(json_input.c_str());
                if (item1) {
                    // Create duplicate
                    item2 = cJSON_Duplicate(item1, 1);
                    if (item2) {
                        // Compare identical parsed objects
                        cJSON_Compare(item1, item2, case_sensitive);
                        
                        // Modify duplicate and compare
                        if (cJSON_IsObject(item2)) {
                            // Add extra property
                            cJSON_AddNumberToObject(item2, 
                                                   fdp.ConsumeRandomLengthString(8).c_str(),
                                                   fdp.ConsumeFloatingPoint<double>());
                            cJSON_Compare(item1, item2, case_sensitive);
                        }
                        
                        cJSON_Delete(item2);
                    }
                    
                    // Create similar but not identical structure
                    cJSON* similar = create_deep_nested_object(fdp, 3, true);
                    if (similar) {
                        cJSON_Compare(item1, similar, case_sensitive);
                        cJSON_Delete(similar);
                    }
                    
                    cJSON_Delete(item1);
                }
            }
            break;
        }
    }
    
    // Cleanup
    if (item1) cJSON_Delete(item1);
    if (item2) cJSON_Delete(item2);
    
    return 0;
}
