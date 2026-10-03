#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <cmath>
#include <cfloat>

extern "C" {
#include "cjson/cJSON.h"
}

// Helper functions to create different cJSON items without recursion
cJSON* create_simple_item(FuzzedDataProvider& fdp, uint8_t type) {
    switch (type) {
        case 0: // cJSON_False
            return cJSON_CreateFalse();
        case 1: // cJSON_True
            return cJSON_CreateTrue();
        case 2: // cJSON_NULL
            return cJSON_CreateNull();
        case 3: { // cJSON_Number
            double value;
            uint8_t num_type = fdp.ConsumeIntegral<uint8_t>() % 8;
            switch (num_type) {
                case 0: value = fdp.ConsumeFloatingPoint<double>(); break;
                case 1: value = 0.0; break;
                case 2: value = -0.0; break;
                case 3: value = HUGE_VAL; break;
                case 4: value = -HUGE_VAL; break;
                case 5: value = NAN; break;
                case 6: value = DBL_MAX; break;
                case 7: value = DBL_MIN; break;
            }
            return cJSON_CreateNumber(value);
        }
        case 4: { // cJSON_String
            std::string str = fdp.ConsumeRandomLengthString(128);
            return cJSON_CreateString(str.c_str());
        }
        case 5: { // cJSON_Array (simple, non-recursive)
            cJSON* array = cJSON_CreateArray();
            if (array) {
                int array_size = fdp.ConsumeIntegralInRange<int>(0, 3);
                for (int i = 0; i < array_size && fdp.remaining_bytes() > 5; i++) {
                    // Only add simple types to avoid recursion
                    uint8_t simple_type = fdp.ConsumeIntegral<uint8_t>() % 5; // 0-4: simple types
                    cJSON* item = create_simple_item(fdp, simple_type);
                    if (item) {
                        cJSON_AddItemToArray(array, item);
                    }
                }
            }
            return array;
        }
        case 6: { // cJSON_Object (simple, non-recursive)
            cJSON* obj = cJSON_CreateObject();
            if (obj) {
                int obj_size = fdp.ConsumeIntegralInRange<int>(0, 3);
                for (int i = 0; i < obj_size && fdp.remaining_bytes() > 10; i++) {
                    std::string key = fdp.ConsumeRandomLengthString(16);
                    // Only add simple types to avoid recursion
                    uint8_t simple_type = fdp.ConsumeIntegral<uint8_t>() % 5; // 0-4: simple types
                    cJSON* value = create_simple_item(fdp, simple_type);
                    if (value) {
                        cJSON_AddItemToObject(obj, key.c_str(), value);
                    }
                }
            }
            return obj;
        }
        case 7: { // cJSON_Raw
            std::string raw = fdp.ConsumeRandomLengthString(128);
            return cJSON_CreateRaw(raw.c_str());
        }
        default:
            return nullptr;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 32) {
        return 0;  // Need minimum input for meaningful comparison testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume test configuration
    uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 8;
    bool case_sensitive = fdp.ConsumeBool();
    
    // Test different scenarios based on consumed value
    switch (test_scenario) {
        case 0: { // Test NULL inputs
            cJSON* item1 = nullptr;
            cJSON* item2 = nullptr;
            
            // All NULL combinations
            cJSON_Compare(nullptr, nullptr, case_sensitive);
            
            if (fdp.remaining_bytes() > 10) {
                item1 = create_simple_item(fdp, fdp.ConsumeIntegral<uint8_t>() % 8);
                cJSON_Compare(item1, nullptr, case_sensitive);
                cJSON_Compare(nullptr, item1, case_sensitive);
            }
            
            if (item1) cJSON_Delete(item1);
            break;
        }
        
        case 1: { // Test type mismatches
            // Create items of different types
            for (int i = 0; i < 3 && fdp.remaining_bytes() > 20; i++) {
                uint8_t type1 = fdp.ConsumeIntegral<uint8_t>() % 8;
                uint8_t type2 = (type1 + 1 + (fdp.ConsumeIntegral<uint8_t>() % 7)) % 8;
                
                cJSON* item1 = create_simple_item(fdp, type1);
                cJSON* item2 = create_simple_item(fdp, type2);
                
                if (item1 && item2) {
                    cJSON_Compare(item1, item2, case_sensitive);
                }
                
                if (item1) cJSON_Delete(item1);
                if (item2) cJSON_Delete(item2);
            }
            break;
        }
        
        case 2: { // Test identical items (should return true)
            if (fdp.remaining_bytes() > 30) {
                uint8_t type = fdp.ConsumeIntegral<uint8_t>() % 8;
                cJSON* item = create_simple_item(fdp, type);
                if (item) {
                    cJSON* duplicate = cJSON_Duplicate(item, 1);
                    if (duplicate) {
                        cJSON_Compare(item, duplicate, case_sensitive);
                        // Also test a == b pointer equality case
                        cJSON_Compare(item, item, case_sensitive);
                        cJSON_Delete(duplicate);
                    }
                    cJSON_Delete(item);
                }
            }
            break;
        }
        
        case 3: { // Test string comparisons with case sensitivity
            std::string str1 = fdp.ConsumeRandomLengthString(64);
            std::string str2 = str1; // Start identical
            
            // Modify str2 based on case sensitivity test
            if (!str2.empty()) {
                if (case_sensitive) {
                    // Make different for case-sensitive comparison
                    if (fdp.ConsumeBool()) {
                        str2[0] = (str2[0] == 'a') ? 'b' : 'a';
                    }
                } else {
                    // Toggle case - should still compare equal for case-insensitive in objects
                    if (isalpha(str2[0])) {
                        if (islower(str2[0])) str2[0] = toupper(str2[0]);
                        else str2[0] = tolower(str2[0]);
                    }
                }
            }
            
            cJSON* str_item1 = cJSON_CreateString(str1.c_str());
            cJSON* str_item2 = cJSON_CreateString(str2.c_str());
            
            if (str_item1 && str_item2) {
                // Direct string comparison (always case-sensitive in cJSON_Compare)
                cJSON_Compare(str_item1, str_item2, case_sensitive);
                
                // Also test in objects for case-sensitive key lookup
                cJSON* obj1 = cJSON_CreateObject();
                cJSON* obj2 = cJSON_CreateObject();
                
                if (obj1 && obj2) {
                    cJSON_AddItemToObject(obj1, "key", cJSON_Duplicate(str_item1, 1));
                    cJSON_AddItemToObject(obj2, "key", cJSON_Duplicate(str_item2, 1));
                    
                    cJSON_Compare(obj1, obj2, case_sensitive);
                    
                    // Test with different keys but same values
                    cJSON* obj3 = cJSON_CreateObject();
                    if (obj3) {
                        std::string key2 = "key";
                        if (!key2.empty() && case_sensitive) {
                            key2[0] = (key2[0] == 'k') ? 'K' : 'k';
                        }
                        cJSON_AddItemToObject(obj3, key2.c_str(), cJSON_Duplicate(str_item1, 1));
                        cJSON_Compare(obj1, obj3, case_sensitive);
                        cJSON_Delete(obj3);
                    }
                    
                    cJSON_Delete(obj1);
                    cJSON_Delete(obj2);
                }
            }
            
            if (str_item1) cJSON_Delete(str_item1);
            if (str_item2) cJSON_Delete(str_item2);
            break;
        }
        
        case 4: { // Test number comparisons with edge cases
            // Create pairs of numbers with interesting relationships
            double values[] = {0.0, -0.0, 1.0, -1.0, 1.000000000000001, 
                              DBL_EPSILON, DBL_MIN, DBL_MAX, HUGE_VAL, -HUGE_VAL, NAN};
            
            for (int i = 0; i < 5 && fdp.remaining_bytes() > 10; i++) {
                int idx1 = fdp.ConsumeIntegralInRange<int>(0, sizeof(values)/sizeof(values[0]) - 1);
                int idx2 = fdp.ConsumeIntegralInRange<int>(0, sizeof(values)/sizeof(values[0]) - 1);
                
                cJSON* num1 = cJSON_CreateNumber(values[idx1]);
                cJSON* num2 = cJSON_CreateNumber(values[idx2]);
                
                if (num1 && num2) {
                    cJSON_Compare(num1, num2, case_sensitive);
                    
                    // Also test integer vs double representation of same value
                    if (fdp.ConsumeBool()) {
                        cJSON* int_num = cJSON_CreateNumber(static_cast<double>(fdp.ConsumeIntegral<int>()));
                        if (int_num) {
                            cJSON_Compare(num1, int_num, case_sensitive);
                            cJSON_Delete(int_num);
                        }
                    }
                }
                
                if (num1) cJSON_Delete(num1);
                if (num2) cJSON_Delete(num2);
            }
            break;
        }
        
        case 5: { // Test array comparisons
            cJSON* array1 = create_simple_item(fdp, 5); // cJSON_Array
            if (array1) {
                // Test with identical array
                cJSON* array2 = cJSON_Duplicate(array1, 1);
                if (array2) {
                    cJSON_Compare(array1, array2, case_sensitive);
                    
                    // Modify array2 to make it different
                    int array_size = cJSON_GetArraySize(array2);
                    if (array_size > 0 && fdp.remaining_bytes() > 5) {
                        int idx = fdp.ConsumeIntegralInRange<int>(0, array_size - 1);
                        cJSON* elem = cJSON_GetArrayItem(array2, idx);
                        if (elem && cJSON_IsNumber(elem)) {
                            cJSON_SetNumberValue(elem, elem->valuedouble + 1.0);
                            cJSON_Compare(array1, array2, case_sensitive);
                        }
                    }
                    
                    // Test with array of different length
                    cJSON* short_array = cJSON_CreateArray();
                    if (short_array) {
                        // Add fewer items
                        for (int i = 0; i < std::max(0, array_size - 1); i++) {
                            cJSON* item = cJSON_GetArrayItem(array1, i);
                            if (item) {
                                cJSON_AddItemToArray(short_array, cJSON_Duplicate(item, 1));
                            }
                        }
                        cJSON_Compare(array1, short_array, case_sensitive);
                        cJSON_Delete(short_array);
                    }
                    
                    cJSON_Delete(array2);
                }
                
                cJSON_Delete(array1);
            }
            break;
        }
        
        case 6: { // Test object comparisons
            cJSON* obj1 = create_simple_item(fdp, 6); // cJSON_Object
            if (obj1) {
                // Test with identical object
                cJSON* obj2 = cJSON_Duplicate(obj1, 1);
                if (obj2) {
                    cJSON_Compare(obj1, obj2, case_sensitive);
                    
                    // Modify obj2 to make it different
                    cJSON* child = obj2->child;
                    if (child && fdp.remaining_bytes() > 5) {
                        // Change a value
                        if (cJSON_IsNumber(child)) {
                            cJSON_SetNumberValue(child, child->valuedouble + 1.0);
                            cJSON_Compare(obj1, obj2, case_sensitive);
                        }
                        
                        // Remove a key (detach item)
                        cJSON* detached = cJSON_DetachItemFromObject(obj2, child->string);
                        if (detached) {
                            cJSON_Compare(obj1, obj2, case_sensitive);
                            cJSON_Delete(detached);
                        }
                    }
                    
                    // Test with object missing a key
                    cJSON* partial_obj = cJSON_CreateObject();
                    if (partial_obj) {
                        // Copy only some items from obj1
                        cJSON* elem;
                        int count = 0;
                        cJSON_ArrayForEach(elem, obj1) {
                            if (count++ % 2 == 0 && elem->string) { // Copy every other item
                                cJSON_AddItemToObject(partial_obj, elem->string, 
                                                     cJSON_Duplicate(elem, 1));
                            }
                        }
                        cJSON_Compare(obj1, partial_obj, case_sensitive);
                        cJSON_Delete(partial_obj);
                    }
                    
                    cJSON_Delete(obj2);
                }
                
                cJSON_Delete(obj1);
            }
            break;
        }
        
        case 7: { // Test complex nested structures
            // Create a deeply nested structure
            cJSON* complex1 = cJSON_CreateObject();
            if (complex1 && fdp.remaining_bytes() > 50) {
                // Add array to object
                cJSON* array = cJSON_CreateArray();
                if (array) {
                    // Add object to array
                    cJSON* nested_obj = cJSON_CreateObject();
                    if (nested_obj) {
                        // Add various types to nested object
                        cJSON_AddStringToObject(nested_obj, "text", 
                                               fdp.ConsumeRandomLengthString(32).c_str());
                        cJSON_AddNumberToObject(nested_obj, "num", 
                                               fdp.ConsumeFloatingPoint<double>());
                        cJSON_AddTrueToObject(nested_obj, "flag");
                        
                        cJSON_AddItemToArray(array, nested_obj);
                    }
                    
                    // Add more items to array
                    for (int i = 0; i < 2 && fdp.remaining_bytes() > 10; i++) {
                        cJSON_AddItemToArray(array, 
                                           cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                    }
                    
                    cJSON_AddItemToObject(complex1, "data", array);
                }
                
                // Add another object with different structure
                cJSON* other_obj = cJSON_CreateObject();
                if (other_obj) {
                    cJSON_AddFalseToObject(other_obj, "enabled");
                    cJSON_AddNullToObject(other_obj, "optional");
                    cJSON_AddItemToObject(complex1, "config", other_obj);
                }
                
                // Create identical copy and compare
                cJSON* complex2 = cJSON_Duplicate(complex1, 1);
                if (complex2) {
                    cJSON_Compare(complex1, complex2, case_sensitive);
                    
                    // Modify deeply and compare
                    cJSON* data_array = cJSON_GetObjectItem(complex2, "data");
                    if (data_array && cJSON_IsArray(data_array)) {
                        cJSON* first_elem = cJSON_GetArrayItem(data_array, 0);
                        if (first_elem && cJSON_IsObject(first_elem)) {
                            cJSON* text_item = cJSON_GetObjectItem(first_elem, "text");
                            if (text_item && cJSON_IsString(text_item)) {
                                // Change string to force comparison failure
                                cJSON_SetValuestring(text_item, "modified");
                                cJSON_Compare(complex1, complex2, case_sensitive);
                            }
                        }
                    }
                    
                    cJSON_Delete(complex2);
                }
                
                cJSON_Delete(complex1);
            }
            break;
        }
    }
    
    return 0;
}
