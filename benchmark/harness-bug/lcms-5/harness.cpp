// Fuzzing harness for Little CMS 2 (lcms) library - Device Link Profile Creation and OkLab Profile
// Target APIs: cmsTransform2DeviceLink (407 undiscovered branches, 0% coverage), 
//              cmsCreate_OkLabProfile (141 undiscovered branches, 0% coverage)
// Helper APIs: cmsCreateTransform, cmsCreate_sRGBProfile, cmsCreateLab2Profile, 
//              cmsDeleteTransform, cmsCloseProfile, cmsCreateProfilePlaceholder
// This harness focuses on device link profile creation workflow and modern OkLab color space support,
// differentiating from previous harnesses:
// - harness_000.cpp: Basic profile parsing and transformations
// - harness_001.cpp: PostScript color resource generation
// - harness_002.cpp: IT8/CGATS file handling and cube file device links
// - harness_003.cpp: Virtual profile creation functions (RGB, Gray, Lab, NULL, BCHSW, device links)

#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <string>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for transform parameters and flags
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Split input for multiple operations
    // Consume fixed-size data first for transform parameters
    cmsUInt32Number intent = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 4);  // 0-4 valid intents
    cmsUInt32Number flags = fdp.ConsumeIntegral<cmsUInt32Number>();
    cmsFloat64Number version = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(2.0, 5.0); // ICC versions 2.x to 5.x
    
    // Determine input and output formats based on fuzzer input
    uint8_t format_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    cmsUInt32Number input_format = 0;
    cmsUInt32Number output_format = 0;
    
    switch (format_choice) {
        case 0:
            input_format = TYPE_RGB_16;
            output_format = TYPE_Lab_16;
            break;
        case 1:
            input_format = TYPE_RGB_8;
            output_format = TYPE_Lab_8;
            break;
        case 2:
            input_format = TYPE_RGB_FLT;
            output_format = TYPE_Lab_FLT;
            break;
        case 3:
            input_format = TYPE_RGB_DBL;
            output_format = TYPE_Lab_DBL;
            break;
    }
    
    // Test 1: Create source and destination profiles for device link creation
    cmsHPROFILE hSrcProfile = NULL;
    cmsHPROFILE hDstProfile = NULL;
    cmsHTRANSFORM hTransform = NULL;
    cmsHPROFILE hDeviceLink = NULL;
    
    // Create source profile (sRGB)
    hSrcProfile = cmsCreate_sRGBProfile();
    if (hSrcProfile == NULL) {
        // If we can't create a basic sRGB profile, something is wrong
        return 0;
    }
    
    // Create destination profile (Lab)
    hDstProfile = cmsCreateLab2Profile(NULL); // Use D50 white point
    if (hDstProfile == NULL) {
        cmsCloseProfile(hSrcProfile);
        return 0;
    }
    
    // Create a color transform between sRGB and Lab
    hTransform = cmsCreateTransform(hSrcProfile, input_format, 
                                     hDstProfile, output_format, 
                                     intent, flags);
    
    if (hTransform != NULL) {
        // Test 2: Convert transform to device link profile - main target API
        // Use fuzzer-provided version and flags
        hDeviceLink = cmsTransform2DeviceLink(hTransform, version, flags);
        
        // If device link creation succeeded, we can test some operations with it
        if (hDeviceLink != NULL) {
            // Simple test: Try to create another transform using the device link
            // This exercises the device link profile in a transformation context
            cmsHTRANSFORM hLinkTransform = cmsCreateTransform(hDeviceLink, input_format,
                                                               hDeviceLink, output_format,
                                                               intent, flags);
            if (hLinkTransform != NULL) {
                cmsDeleteTransform(hLinkTransform);
            }
            
            // Clean up device link profile
            cmsCloseProfile(hDeviceLink);
        }
        
        // Clean up the original transform
        cmsDeleteTransform(hTransform);
    }
    
    // Test 3: Create OkLab profile - second target API
    // cmsCreate_OkLabProfile takes a context parameter (can be NULL for default context)
    cmsHPROFILE hOkLabProfile = cmsCreate_OkLabProfile(NULL);
    if (hOkLabProfile != NULL) {
        // Test the OkLab profile by creating a simple transform
        // OkLab is a color space profile, so we can create a transform from sRGB to OkLab
        cmsHTRANSFORM hOkLabTransform = cmsCreateTransform(hSrcProfile, input_format,
                                                            hOkLabProfile, output_format,
                                                            intent, flags);
        if (hOkLabTransform != NULL) {
            // Test a small transformation with random data from fuzzer input
            if (fdp.remaining_bytes() >= 12) {
                // Consume some bytes for test color data
                std::vector<uint8_t> test_input = fdp.ConsumeBytes<uint8_t>(12);
                uint8_t test_output[12] = {0};
                
                // Only attempt transformation if we have valid data
                if (test_input.size() == 12) {
                    // Note: This may fail depending on format compatibility, but that's OK
                    // The goal is to exercise the API paths, not necessarily succeed
                    cmsDoTransform(hOkLabTransform, test_input.data(), test_output, 1);
                }
            }
            
            cmsDeleteTransform(hOkLabTransform);
        }
        
        cmsCloseProfile(hOkLabProfile);
    }
    
    // Test 4: Optional - Test cmsCreateProfilePlaceholder helper API
    // This is used internally by cmsTransform2DeviceLink
    cmsHPROFILE hPlaceholder = cmsCreateProfilePlaceholder(NULL);
    if (hPlaceholder != NULL) {
        // Set some basic properties on the placeholder
        cmsSetProfileVersion(hPlaceholder, version);
        
        // Try to set device class (may or may not succeed depending on state)
        cmsSetDeviceClass(hPlaceholder, cmsSigLinkClass);
        
        cmsCloseProfile(hPlaceholder);
    }
    
    // Clean up source and destination profiles
    if (hSrcProfile != NULL) {
        cmsCloseProfile(hSrcProfile);
    }
    if (hDstProfile != NULL) {
        cmsCloseProfile(hDstProfile);
    }
    
    return 0;
}
