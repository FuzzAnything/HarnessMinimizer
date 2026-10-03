// Little CMS (lcms) fuzzing harness for tag operations and tone curve building
// Targets APIs: cmsCreateContext, cmsReadTag, cmsWriteTag, cmsBuild* tone curves,
// cmsCreate_OkLabProfile, and profile creation APIs
// Uses FuzzedDataProvider for structured input splitting
// Semantically different from harness_000.cpp which focuses on ICC profile processing

#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <climits>
#include <cfloat>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need at least some bytes for basic operations
    if (size < 32) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Strategy: Test different tag operations and tone curve building scenarios
    
    // Create a context first (optional but tests context API)
    cmsContext context = cmsCreateContext(NULL, NULL);
    
    // Consume operation type to determine test scenario
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Helper function to get random tag signature from fuzzer input
    auto get_random_tag = [&fdp]() -> cmsTagSignature {
        uint32_t tag_val = fdp.ConsumeIntegral<uint32_t>();
        // Map to some common ICC tags
        switch (tag_val % 20) {
            case 0: return cmsSigMediaWhitePointTag;
            case 1: return cmsSigMediaBlackPointTag;
            case 2: return cmsSigCopyrightTag;
            case 3: return cmsSigProfileDescriptionTag;
            case 4: return cmsSigDeviceMfgDescTag;
            case 5: return cmsSigDeviceModelDescTag;
            case 6: return cmsSigViewingCondDescTag;
            case 7: return cmsSigViewingConditionsTag;
            case 8: return cmsSigLuminanceTag;
            case 9: return cmsSigMeasurementTag;
            case 10: return cmsSigTechnologyTag;
            case 11: return cmsSigCharTargetTag;
            case 12: return cmsSigColorantTableTag;
            case 13: return cmsSigColorantTableOutTag;
            case 14: return cmsSigColorimetricIntentImageStateTag;
            case 15: return cmsSigPerceptualRenderingIntentGamutTag;
            case 16: return cmsSigSaturationRenderingIntentGamutTag;
            case 17: return cmsSigProfileSequenceDescTag;
            case 18: return cmsSigPreview0Tag;
            case 19: return cmsSigPreview1Tag;
            default: return cmsSigProfileDescriptionTag;
        }
    };

    switch (operation) {
        case 0: {
            // Test 1: Tone curve building and manipulation
            uint8_t curve_type = fdp.ConsumeIntegral<uint8_t>() % 5;
            
            cmsToneCurve* curve = NULL;
            
            switch (curve_type) {
                case 0: {
                    // Build parametric tone curve
                    int32_t param_type = fdp.ConsumeIntegral<int32_t>() % 5; // 0-4 parametric types
                    double params[10];
                    size_t num_params = 0;
                    
                    // Determine number of parameters based on type
                    switch (param_type) {
                        case 0: num_params = 1; break; // Type 0: Y = X^g
                        case 1: num_params = 3; break; // Type 1: Y = (aX + b)^g + c
                        case 2: num_params = 4; break; // Type 2: Y = (aX + b)^g + c, X >= -b/a
                        case 3: num_params = 5; break; // Type 3: Y = (aX + b)^g + c, X <= d
                        case 4: num_params = 7; break; // Type 4: Y = (aX + b)^g + c, d <= X <= e
                        default: num_params = 1;
                    }
                    
                    // Consume parameters from fuzzer input
                    for (size_t i = 0; i < num_params && fdp.remaining_bytes() >= sizeof(double); i++) {
                        params[i] = fdp.ConsumeFloatingPoint<double>();
                        // Clamp to reasonable range
                        params[i] = std::max(-100.0, std::min(100.0, params[i]));
                    }
                    
                    curve = cmsBuildParametricToneCurve(context, param_type, params);
                    break;
                }
                
                case 1: {
                    // Build gamma tone curve
                    double gamma = 2.2; // Default
                    if (fdp.remaining_bytes() >= sizeof(double)) {
                        gamma = fdp.ConsumeFloatingPoint<double>();
                        gamma = std::max(0.1, std::min(10.0, gamma)); // Clamp to reasonable range
                    }
                    curve = cmsBuildGamma(context, gamma);
                    break;
                }
                
                case 2: {
                    // Build tabulated tone curve (16-bit)
                    size_t num_entries = fdp.ConsumeIntegralInRange<size_t>(2, 256);
                    if (fdp.remaining_bytes() < num_entries * sizeof(uint16_t)) {
                        num_entries = std::min(num_entries, fdp.remaining_bytes() / sizeof(uint16_t));
                    }
                    
                    if (num_entries >= 2) {
                        std::vector<uint16_t> values(num_entries);
                        for (size_t i = 0; i < num_entries && fdp.remaining_bytes() >= sizeof(uint16_t); i++) {
                            values[i] = fdp.ConsumeIntegral<uint16_t>();
                        }
                        curve = cmsBuildTabulatedToneCurve16(context, num_entries, values.data());
                    }
                    break;
                }
                
                case 3: {
                    // Build tabulated tone curve (float)
                    size_t num_entries = fdp.ConsumeIntegralInRange<size_t>(2, 256);
                    if (fdp.remaining_bytes() < num_entries * sizeof(float)) {
                        num_entries = std::min(num_entries, fdp.remaining_bytes() / sizeof(float));
                    }
                    
                    if (num_entries >= 2) {
                        std::vector<float> values(num_entries);
                        for (size_t i = 0; i < num_entries && fdp.remaining_bytes() >= sizeof(float); i++) {
                            values[i] = fdp.ConsumeFloatingPoint<float>();
                            // Clamp to [0, 1] range for tone curves
                            values[i] = std::max(0.0f, std::min(1.0f, values[i]));
                        }
                        curve = cmsBuildTabulatedToneCurveFloat(context, num_entries, values.data());
                    }
                    break;
                }
                
                case 4: {
                    // Build segmented tone curve
                    size_t num_segments = fdp.ConsumeIntegralInRange<size_t>(1, 10);
                    if (num_segments > 0 && fdp.remaining_bytes() >= num_segments * sizeof(cmsCurveSegment)) {
                        std::vector<cmsCurveSegment> segments(num_segments);
                        for (size_t i = 0; i < num_segments; i++) {
                            // For parametric segments, we need to set Type and Params
                            segments[i].x0 = fdp.ConsumeFloatingPoint<float>();
                            segments[i].x1 = fdp.ConsumeFloatingPoint<float>();
                            segments[i].Type = fdp.ConsumeIntegral<int32_t>() % 5;
                            
                            // Clamp domain coordinates
                            segments[i].x0 = std::max(0.0f, std::min(1.0f, segments[i].x0));
                            segments[i].x1 = std::max(0.0f, std::min(1.0f, segments[i].x1));
                            
                            // Ensure x0 <= x1
                            if (segments[i].x0 > segments[i].x1) {
                                std::swap(segments[i].x0, segments[i].x1);
                            }
                            
                            // Initialize parameters array
                            for (int j = 0; j < 10; j++) {
                                segments[i].Params[j] = 0.0;
                            }
                            
                            // Set some parameters based on fuzzer input if available
                            if (segments[i].Type != 0 && fdp.remaining_bytes() >= sizeof(double)) {
                                // For parametric curves, set first parameter from fuzzer input
                                segments[i].Params[0] = fdp.ConsumeFloatingPoint<double>();
                                segments[i].Params[0] = std::max(-100.0, std::min(100.0, segments[i].Params[0]));
                            }
                            
                            // For sampled segments (Type == 0), we'd need to set nGridPoints and SampledPoints
                            // but that's more complex, so we'll mostly test parametric segments
                            segments[i].nGridPoints = 0;
                            segments[i].SampledPoints = NULL;
                        }
                        curve = cmsBuildSegmentedToneCurve(context, num_segments, segments.data());
                    }
                    break;
                }
            }
            
            // If curve was created, test some operations on it
            if (curve != NULL) {
                // Evaluate curve at some points
                for (int i = 0; i < 5 && fdp.remaining_bytes() >= sizeof(float); i++) {
                    float input = fdp.ConsumeFloatingPoint<float>();
                    input = std::max(0.0f, std::min(1.0f, input)); // Clamp to [0,1]
                    float output = cmsEvalToneCurveFloat(curve, input);
                    (void)output; // Suppress unused warning
                }
                
                // Get reverse curve if possible
                cmsToneCurve* reverse_curve = cmsReverseToneCurve(curve);
                if (reverse_curve != NULL) {
                    cmsFreeToneCurve(reverse_curve);
                }
                
                // Check if curve is monotonic
                cmsBool is_monotonic = cmsIsToneCurveMonotonic(curve);
                (void)is_monotonic;
                
                // Check if curve is multisegment
                cmsBool is_multisegment = cmsIsToneCurveMultisegment(curve);
                (void)is_multisegment;
                
                // Get estimated table entries
                cmsUInt32Number estimated_entries = cmsGetToneCurveEstimatedTableEntries(curve);
                (void)estimated_entries;
                
                cmsFreeToneCurve(curve);
            }
            break;
        }
        
        case 1: {
            // Test 2: Tag reading/writing operations
            // First create a simple profile to work with
            cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
            if (hProfile == NULL) {
                // Try creating XYZ profile as fallback
                hProfile = cmsCreateXYZProfile();
            }
            
            if (hProfile != NULL) {
                // Test reading various tags
                cmsTagSignature tag_to_read = get_random_tag();
                void* tag_data = cmsReadTag(hProfile, tag_to_read);
                (void)tag_data; // Suppress unused warning
                
                // Test writing tags (only if we have data to write)
                if (fdp.remaining_bytes() > 16) {
                    cmsTagSignature tag_to_write = get_random_tag();
                    
                    // Create some tag data based on tag type
                    size_t data_size = fdp.ConsumeIntegralInRange<size_t>(16, 256);
                    data_size = std::min(data_size, fdp.remaining_bytes());
                    
                    if (data_size > 0) {
                        std::vector<uint8_t> tag_buffer(data_size);
                        std::vector<uint8_t> consumed_data = fdp.ConsumeBytes<uint8_t>(data_size);
                        memcpy(tag_buffer.data(), consumed_data.data(), data_size);
                        
                        // Try writing the tag using cmsWriteRawTag which accepts arbitrary binary data
                        // Ensure size fits into cmsUInt32Number
                        cmsUInt32Number write_size = (data_size > UINT_MAX) ? UINT_MAX : static_cast<cmsUInt32Number>(data_size);
                        cmsBool write_success = cmsWriteRawTag(hProfile, tag_to_write, tag_buffer.data(), write_size);
                        
                        // Try reading it back
                        void* written_tag_data = cmsReadTag(hProfile, tag_to_write);
                        (void)written_tag_data;
                    }
                }
                
                // Test tag existence checking
                for (int i = 0; i < 5; i++) {
                    cmsTagSignature test_tag = get_random_tag();
                    cmsBool tag_exists = cmsIsTag(hProfile, test_tag);
                    (void)tag_exists;
                }
                
                // Test getting profile info
                char profile_info[256];
                cmsGetProfileInfoASCII(hProfile, cmsInfoDescription, "en", "US", 
                                      profile_info, sizeof(profile_info));
                
                cmsCloseProfile(hProfile);
            }
            break;
        }
        
        case 2: {
            // Test 3: Create and manipulate OkLab profile
            cmsHPROFILE okLabProfile = cmsCreate_OkLabProfile(context);
            if (okLabProfile != NULL) {
                // Test profile properties
                cmsColorSpaceSignature colorSpace = cmsGetColorSpace(okLabProfile);
                cmsProfileClassSignature profileClass = cmsGetDeviceClass(okLabProfile);
                cmsUInt32Number profileVersion = cmsGetProfileVersion(okLabProfile);
                (void)colorSpace; (void)profileClass; (void)profileVersion;
                
                // Create a transform from sRGB to OkLab
                cmsHPROFILE sRGBProfile = cmsCreate_sRGBProfile();
                if (sRGBProfile != NULL) {
                    uint8_t intent = fdp.ConsumeIntegral<uint8_t>() % 4;
                    cmsUInt32Number flags = fdp.ConsumeIntegral<uint32_t>();
                    
                    cmsHTRANSFORM hTransform = cmsCreateTransform(
                        sRGBProfile,
                        TYPE_RGB_8,
                        okLabProfile,
                        TYPE_Lab_DBL, // OkLab uses Lab-like format
                        intent,
                        flags
                    );
                    
                    if (hTransform != NULL) {
                        // Test transform with some pixel data
                        if (fdp.remaining_bytes() >= 3) { // RGB has 3 channels
                            std::vector<uint8_t> rgb_pixel(3);
                            std::vector<double> lab_pixel(3);
                            
                            std::vector<uint8_t> pixel_data = fdp.ConsumeBytes<uint8_t>(3);
                            memcpy(rgb_pixel.data(), pixel_data.data(), 3);
                            
                            cmsDoTransform(hTransform, rgb_pixel.data(), lab_pixel.data(), 1);
                        }
                        
                        cmsDeleteTransform(hTransform);
                    }
                    
                    cmsCloseProfile(sRGBProfile);
                }
                
                cmsCloseProfile(okLabProfile);
            }
            break;
        }
        
        case 3: {
            // Test 4: Advanced profile creation and tag manipulation
            // Create a placeholder profile
            cmsHPROFILE placeholder = cmsCreateProfilePlaceholder(context);
            if (placeholder != NULL) {
                // Set some basic profile properties
                cmsSetProfileVersion(placeholder, 0x02400000); // ICC 2.4
                cmsSetDeviceClass(placeholder, cmsSigInputClass);
                cmsSetColorSpace(placeholder, cmsSigRgbData);
                cmsSetPCS(placeholder, cmsSigXYZData);
                
                // Create and set a tone curve for RGB channels
                cmsToneCurve* gamma_curve = cmsBuildGamma(context, 2.2);
                if (gamma_curve != NULL) {
                    cmsToneCurve* curves[3] = {gamma_curve, gamma_curve, gamma_curve};
                    cmsBool set_success = cmsWriteTag(placeholder, cmsSigRedTRCTag, curves[0]);
                    set_success = cmsWriteTag(placeholder, cmsSigGreenTRCTag, curves[1]);
                    set_success = cmsWriteTag(placeholder, cmsSigBlueTRCTag, curves[2]);
                    (void)set_success;
                    
                    cmsFreeToneCurve(gamma_curve);
                }
                
                // Try to save the created profile to memory
                cmsUInt32Number bytesNeeded = 0;
                cmsSaveProfileToMem(placeholder, NULL, &bytesNeeded);
                
                if (bytesNeeded > 0 && bytesNeeded < 10 * 1024 * 1024) { // Reasonable size limit
                    std::vector<uint8_t> saved_profile(bytesNeeded);
                    cmsBool save_success = cmsSaveProfileToMem(placeholder, saved_profile.data(), &bytesNeeded);
                    (void)save_success;
                    
                    // Try to open the saved profile
                    if (save_success && bytesNeeded > 0) {
                        cmsHPROFILE reopened = cmsOpenProfileFromMem(saved_profile.data(), bytesNeeded);
                        if (reopened != NULL) {
                            cmsCloseProfile(reopened);
                        }
                    }
                }
                
                cmsCloseProfile(placeholder);
            }
            break;
        }
    }
    
    // Clean up context
    if (context != NULL) {
        cmsDeleteContext(context);
    }
    
    return 0;
}
