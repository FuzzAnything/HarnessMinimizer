/*
 * Fuzzing harness for cJSON_SetNumberHelper function
 * Targets: cJSON_SetNumberHelper, cJSON_CreateNumber, cJSON_GetNumberValue, cJSON_Delete
 * 
 * This harness specifically targets the 6 undiscovered branches in cJSON_SetNumberHelper:
 * 1. NULL object check branch (returns NAN)
 * 2. number >= INT_MAX branch (saturation to INT_MAX)
 * 3. number <= INT_MIN branch (saturation to INT_MIN)
 * 4. else branch (normal conversion)
 * 5. Return value assignment branch
 * 6. Edge case handling in combination with cJSON_GetNumberValue
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <climits>
#include "cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for at least one operation
    if (size < sizeof(double) + 1) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume operation selector: 0-3 for different test scenarios
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Create a number object first
    double initial_value = 0.0;
    if (fdp.remaining_bytes() >= sizeof(double)) {
        initial_value = fdp.ConsumeFloatingPoint<double>();
    }
    
    cJSON* number_obj = cJSON_CreateNumber(initial_value);
    if (number_obj == NULL) {
        // If creation fails, nothing to test
        return 0;
    }
    
    double test_number = 0.0;
    bool use_null_object = false;
    
    switch (operation) {
        case 0: {
            // Test with INT_MAX boundary values
            // Generate numbers around INT_MAX
            if (fdp.remaining_bytes() >= sizeof(double)) {
                double offset = fdp.ConsumeFloatingPointInRange<double>(0.0, 10000.0);
                // Create numbers >= INT_MAX
                test_number = (double)INT_MAX + offset;
            }
            break;
        }
        case 1: {
            // Test with INT_MIN boundary values  
            // Generate numbers around INT_MIN
            if (fdp.remaining_bytes() >= sizeof(double)) {
                double offset = fdp.ConsumeFloatingPointInRange<double>(0.0, 10000.0);
                // Create numbers <= INT_MIN
                test_number = (double)INT_MIN - offset;
            }
            break;
        }
        case 2: {
            // Test with normal values (between INT_MIN and INT_MAX)
            if (fdp.remaining_bytes() >= sizeof(double)) {
                test_number = fdp.ConsumeFloatingPointInRange<double>((double)INT_MIN + 1.0, (double)INT_MAX - 1.0);
            }
            break;
        }
        case 3: {
            // Test special floating-point values: NaN, infinity
            if (fdp.remaining_bytes() >= 1) {
                uint8_t special_type = fdp.ConsumeIntegral<uint8_t>() % 3;
                switch (special_type) {
                    case 0:
                        test_number = NAN;
                        break;
                    case 1:
                        test_number = INFINITY;
                        break;
                    case 2:
                        test_number = -INFINITY;
                        break;
                }
            }
            // Also test NULL object case
            use_null_object = (fdp.ConsumeBool() && fdp.remaining_bytes() > 0);
            break;
        }
    }
    
    // If we have remaining bytes, maybe test with NULL object
    if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) {
        use_null_object = true;
    }
    
    cJSON* target_object = use_null_object ? NULL : number_obj;
    
    // Call cJSON_SetNumberHelper with the test number
    double result = cJSON_SetNumberHelper(target_object, test_number);
    
    if (use_null_object) {
        // When object is NULL, should return NAN
        // Check if result is NaN (note: direct comparison with NAN is not reliable)
        if (!std::isnan(result)) {
            // This might indicate an issue, but we continue testing
        }
    } else {
        // When object is valid, verify the number was set correctly
        // First check with cJSON_GetNumberValue
        double retrieved_value = cJSON_GetNumberValue(number_obj);
        
        // For non-NaN/Infinity values, verify the value was set
        if (!std::isnan(test_number) && !std::isinf(test_number)) {
            // The function should have set the value
            // Note: Due to floating point precision, we check approximate equality
            double diff = fabs(retrieved_value - test_number);
            if (diff > 0.0001) {
                // Significant difference, but we continue testing
            }
            
            // Also verify the saturation logic worked
            // Check valueint for saturation cases
            if (test_number >= INT_MAX) {
                if (number_obj->valueint != INT_MAX) {
                    // Should have been saturated to INT_MAX
                }
            } else if (test_number <= (double)INT_MIN) {
                if (number_obj->valueint != INT_MIN) {
                    // Should have been saturated to INT_MIN
                }
            } else {
                // Should be normal conversion (may lose precision)
                int expected_int = (int)test_number;
                if (number_obj->valueint != expected_int) {
                    // May differ due to rounding, but we continue
                }
            }
        }
        
        // Verify the return value matches what was set
        double return_diff = fabs(result - retrieved_value);
        if (return_diff > 0.0001) {
            // Return value should match the set value
        }
    }
    
    // Clean up
    if (!use_null_object) {
        cJSON_Delete(number_obj);
    }
    
    // Test additional edge case: call cJSON_SetNumberHelper with NULL object explicitly
    double nan_result = cJSON_SetNumberHelper(NULL, test_number);
    if (!std::isnan(nan_result)) {
        // Should return NAN for NULL object
    }
    
    // Test another edge case: create multiple objects and set different values
    if (fdp.remaining_bytes() >= sizeof(double)) {
        double another_value = fdp.ConsumeFloatingPoint<double>();
        cJSON* another_obj = cJSON_CreateNumber(another_value);
        if (another_obj != NULL) {
            double set_result = cJSON_SetNumberHelper(another_obj, test_number);
            double get_result = cJSON_GetNumberValue(another_obj);
            
            // Verify consistency
            double consistency_diff = fabs(set_result - get_result);
            if (consistency_diff > 0.0001) {
                // Should be consistent
            }
            
            cJSON_Delete(another_obj);
        }
    }
    
    return 0;
}
