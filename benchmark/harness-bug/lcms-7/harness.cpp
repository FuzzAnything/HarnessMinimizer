//---------------------------------------------------------------------------------
//
//  Little Color Management System (lcms) Fuzzing Harness
//  Targets proofing transform operations for soft proofing workflows
//
//  This harness exercises proofing transform APIs:
//  1. cmsCreateProofingTransformTHR - Thread-safe proofing transform creation (0% coverage)
//  2. cmsCreateProofingTransform - Proofing transform creation wrapper
//  3. cmsOpenProfileFromMemTHR - Thread-safe profile opening from memory
//  4. cmsOpenProfileFromMem - Profile opening from memory
//  5. cmsCreateLab2Profile - Lab profile creation (0% coverage)
//  6. cmsCreateNULLProfile - NULL profile creation (0% coverage)
//  7. cmsDeleteTransform - Transform cleanup
//  8. cmsCloseProfile - Profile cleanup
//
//  Proofing transforms are critical for professional color management workflows
//  (soft proofing). This harness targets 460+ points of undiscovered branch
//  complexity - the highest among all uncovered APIs in lcms.
//
//  OPTIMIZATION STRATEGY:
//  - Simple input consumption with minimal branching
//  - Focus on core proofing transform lifecycle
//  - Use both memory-based and built-in profile creation
//  - Clean resource management to prevent leaks
//  - Optional transform usage with sample data
//
//---------------------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check
    // We need: operation_type (1 byte) + flags (4 bytes) + intents (2 bytes) 
    // + format types (8 bytes) + minimal profile data = ~128 bytes
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size parameters first
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;  // 0-3 for different test paths
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    uint8_t intent = fdp.ConsumeIntegral<uint8_t>() % 4;          // 0-3 rendering intents
    uint8_t proofing_intent = fdp.ConsumeIntegral<uint8_t>() % 4; // 0-3 proofing intents
    
    // Consume format types - using common format types
    uint32_t input_format = fdp.ConsumeIntegral<uint32_t>();
    uint32_t output_format = fdp.ConsumeIntegral<uint32_t>();
    
    // Consume white point for Lab profile if needed
    double white_x = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double white_y = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double white_z = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    
    cmsCIExyY white_point;
    white_point.x = white_x;
    white_point.y = white_y;
    white_point.Y = white_z;
    
    // Create a context for thread-safe operations
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) return 0;
    
    // Variables for cleanup
    cmsHPROFILE src_profile = NULL;
    cmsHPROFILE dst_profile = NULL;
    cmsHPROFILE proofing_profile = NULL;
    cmsHTRANSFORM transform = NULL;
    cmsHTRANSFORM transform2 = NULL;
    
    // Determine profile creation strategy based on operation_type
    switch (operation_type) {
        case 0: {
            // Use NULL profile as source, Lab profile as proofing
            src_profile = cmsCreateNULLProfileTHR(context);
            proofing_profile = cmsCreateLab2ProfileTHR(context, &white_point);
            
            // Use sRGB as destination (common case)
            dst_profile = cmsCreate_sRGBProfileTHR(context);
            break;
        }
        
        case 1: {
            // Use memory-based profiles
            // Consume some data for profile creation
            size_t profile_data_size = fdp.ConsumeIntegralInRange<size_t>(128, 4096);
            if (profile_data_size > fdp.remaining_bytes()) {
                profile_data_size = fdp.remaining_bytes();
            }
            
            std::vector<uint8_t> profile_data = fdp.ConsumeBytes<uint8_t>(profile_data_size);
            
            if (profile_data.size() > 0) {
                // Try to open profiles from memory
                src_profile = cmsOpenProfileFromMemTHR(context, profile_data.data(), profile_data.size());
                proofing_profile = cmsOpenProfileFromMemTHR(context, profile_data.data(), profile_data.size());
                
                // If memory profiles failed, create default profiles
                if (!src_profile) {
                    src_profile = cmsCreateNULLProfileTHR(context);
                }
                if (!proofing_profile) {
                    proofing_profile = cmsCreateLab2ProfileTHR(context, &white_point);
                }
            }
            
            // Use sRGB as destination
            dst_profile = cmsCreate_sRGBProfileTHR(context);
            break;
        }
        
        case 2: {
            // Use NULL profile for all three (simple case)
            src_profile = cmsCreateNULLProfileTHR(context);
            dst_profile = cmsCreateNULLProfileTHR(context);
            proofing_profile = cmsCreateNULLProfileTHR(context);
            break;
        }
        
        case 3: {
            // Mixed approach: source from memory, others built-in
            size_t profile_data_size = fdp.ConsumeIntegralInRange<size_t>(128, 2048);
            if (profile_data_size > fdp.remaining_bytes()) {
                profile_data_size = fdp.remaining_bytes();
            }
            
            std::vector<uint8_t> profile_data = fdp.ConsumeBytes<uint8_t>(profile_data_size);
            
            if (profile_data.size() > 0) {
                src_profile = cmsOpenProfileFromMemTHR(context, profile_data.data(), profile_data.size());
            }
            
            if (!src_profile) {
                src_profile = cmsCreateNULLProfileTHR(context);
            }
            
            dst_profile = cmsCreate_sRGBProfileTHR(context);
            proofing_profile = cmsCreateLab2ProfileTHR(context, &white_point);
            break;
        }
    }
    
    // Check if we have valid profiles
    if (!src_profile || !dst_profile || !proofing_profile) {
        // Cleanup any created profiles
        if (src_profile) cmsCloseProfile(src_profile);
        if (dst_profile) cmsCloseProfile(dst_profile);
        if (proofing_profile) cmsCloseProfile(proofing_profile);
        cmsDeleteContext(context);
        return 0;
    }
    
    // Create proofing transform using THR version (primary target)
    transform = cmsCreateProofingTransformTHR(context,
                                             src_profile,
                                             input_format,
                                             dst_profile,
                                             output_format,
                                             proofing_profile,
                                             intent,
                                             proofing_intent,
                                             flags);
    
    // Also test the non-THR wrapper function if THR version succeeded
    if (transform) {
        transform2 = cmsCreateProofingTransform(src_profile,
                                               input_format,
                                               dst_profile,
                                               output_format,
                                               proofing_profile,
                                               intent,
                                               proofing_intent,
                                               flags);
        
        // Optional: Use the transform with sample data if we have remaining input
        if (fdp.remaining_bytes() > 0 && transform) {
            // Simple test with a small buffer
            size_t sample_size = fdp.ConsumeIntegralInRange<size_t>(1, 256);
            if (sample_size > fdp.remaining_bytes()) {
                sample_size = fdp.remaining_bytes();
            }
            
            std::vector<uint8_t> input_buffer = fdp.ConsumeBytes<uint8_t>(sample_size);
            std::vector<uint8_t> output_buffer(sample_size);
            
            if (input_buffer.size() > 0 && output_buffer.size() > 0) {
                // Try to use the transform with the sample data
                // Note: This may fail if formats don't match, but that's OK for fuzzing
                cmsDoTransform(transform, input_buffer.data(), output_buffer.data(), 1);
            }
        }
    }
    
    // Cleanup transforms
    if (transform) cmsDeleteTransform(transform);
    if (transform2) cmsDeleteTransform(transform2);
    
    // Cleanup profiles
    cmsCloseProfile(src_profile);
    cmsCloseProfile(dst_profile);
    cmsCloseProfile(proofing_profile);
    
    // Cleanup context
    cmsDeleteContext(context);
    
    return 0;
}
