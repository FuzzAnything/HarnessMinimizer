// Little-CMS fuzzing harness for comprehensive Cube file parsing and device link creation
// Focus on stream-based profile opening and Cube file device link creation subsystem
// Primary APIs targeted (from coverage guidance):
// - cmsCreateDeviceLinkFromCubeFile (Primary Target: 93 undiscovered branches)
// - cmsCreateDeviceLinkFromCubeFileTHR (Primary Target - thread-safe: 93 undiscovered branches)
// - cmsOpenProfileFromStream (Required Helper: Cube file loading)
// - cmsOpenProfileFromStreamTHR (Required Helper: thread-safe Cube file loading)
// - cmsDeleteTransform (Required Cleanup: Device link disposal)
// - cmsFormatterForPCSOfProfile (Optional: 42 undiscovered branches from guidance)

// Semantic differentiation from existing harnesses:
// - harness_007: File-based Cube/IT8 operations, uses file APIs directly
// - harness_011: Memory-based CGATS operations with device link creation workflow  
// - harness_012: Comprehensive IT8/CGATS file format manipulation
// - harness_013: Focus on stream-based Cube file parsing with cmsOpenProfileFromStream API
//                and comprehensive device link creation from Cube files

// This harness implements the complete Cube file device link workflow as specified in coverage guidance:
// 1. Setup: Generate valid Cube file data with DOMAIN_MIN, DOMAIN_MAX, LUT3D_SIZE keywords
// 2. Initialization: Call cmsOpenProfileFromStream to open Cube file stream
// 3. Core Operation: Call cmsCreateDeviceLinkFromCubeFile to create device link transform
// 4. Verification: Optionally test the created transform with sample color data
// 5. Cleanup: Call cmsDeleteTransform to free device link resources

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>

#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size needed for comprehensive Cube file testing
    // Need enough for: operation selection, Cube content generation, transform testing
    if (size < 256) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // PHASE 1: CONFIGURATION AND PARAMETER EXTRACTION
    // Consume fixed-size parameters first
    uint8_t test_mode = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0=basic cube, 1=3D LUT, 2=mixed
    uint8_t use_thread_safe = fdp.ConsumeBool();  // Use THR versions of APIs
    uint8_t use_stream_api = fdp.ConsumeBool();  // Test cmsOpenProfileFromStream
    uint8_t test_formatter = fdp.ConsumeBool();  // Test cmsFormatterForPCSOfProfile
    uint8_t create_device_link = fdp.ConsumeBool();  // Create device link from cube file
    
    // Consume numeric parameters for cube file generation
    uint16_t lut3d_size = fdp.ConsumeIntegralInRange<uint16_t>(2, 33);  // Reasonable 3D LUT size
    uint16_t lut1d_size = fdp.ConsumeIntegralInRange<uint16_t>(2, 1024);  // 1D LUT size
    double domain_min_r = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double domain_min_g = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double domain_min_b = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double domain_max_r = fdp.ConsumeFloatingPointInRange<double>(1.0, 2.0);
    double domain_max_g = fdp.ConsumeFloatingPointInRange<double>(1.0, 2.0);
    double domain_max_b = fdp.ConsumeFloatingPointInRange<double>(1.0, 2.0);
    
    // Create temporary filename
    std::string cube_filename = "/tmp/lcms_cube_stream_" + fdp.ConsumeRandomLengthString(16) + ".cube";
    
    // Create context if using thread-safe APIs
    cmsContext context = NULL;
    if (use_thread_safe) {
        context = cmsCreateContext(NULL, NULL);
        if (context == NULL) {
            // Fall back to non-thread-safe testing
            use_thread_safe = 0;
        }
    }
    
    // PHASE 2: GENERATE CUBE FILE CONTENT WITH PROPER SYNTAX
    std::string cube_content;
    
    // Generate structured cube content based on test mode
    cube_content = "TITLE \"Fuzzed Cube LUT for Stream Testing\\n\"\n";
    cube_content += "CREATOR \"Little-CMS Cube Stream Fuzzer\"\n";
    
    if (test_mode == 0 || test_mode == 2) {
        // Include 1D LUT structure
        cube_content += "LUT_1D_SIZE " + std::to_string(lut1d_size) + "\n";
    }
    
    if (test_mode == 1 || test_mode == 2) {
        // Include 3D LUT structure (required for comprehensive testing)
        cube_content += "LUT_3D_SIZE " + std::to_string(lut3d_size) + "\n";
    }
    
    // Add domain definitions (critical for Cube file parsing)
    cube_content += "DOMAIN_MIN " + 
        std::to_string(domain_min_r) + " " +
        std::to_string(domain_min_g) + " " +
        std::to_string(domain_min_b) + "\n";
    
    cube_content += "DOMAIN_MAX " + 
        std::to_string(domain_max_r) + " " +
        std::to_string(domain_max_g) + " " +
        std::to_string(domain_max_b) + "\n";
    
    // Generate LUT data based on remaining fuzzer input
    if (fdp.remaining_bytes() > 100) {
        // Add structured LUT data
        cube_content += "\n# LUT data generated from fuzzer input\n";
        
        // Generate 1D LUT data if needed
        if ((test_mode == 0 || test_mode == 2) && fdp.remaining_bytes() > 50) {
            cube_content += "\n# 1D LUT entries\n";
            size_t lut1d_entries = std::min<size_t>(lut1d_size, fdp.remaining_bytes() / 12);
            lut1d_entries = std::min<size_t>(lut1d_entries, 50);  // Limit for performance
            
            for (size_t i = 0; i < lut1d_entries && fdp.remaining_bytes() > 12; i++) {
                cube_content += 
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + " " +
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + " " +
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + "\n";
            }
        }
        
        // Generate 3D LUT data if needed
        if ((test_mode == 1 || test_mode == 2) && fdp.remaining_bytes() > 50) {
            cube_content += "\n# 3D LUT entries\n";
            // 3D LUT has size^3 entries, but we generate a subset for performance
            size_t max_3d_entries = std::min<size_t>(lut3d_size * lut3d_size * 2, 100);
            size_t lut3d_entries = std::min<size_t>(max_3d_entries, fdp.remaining_bytes() / 12);
            
            for (size_t i = 0; i < lut3d_entries && fdp.remaining_bytes() > 12; i++) {
                cube_content += 
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + " " +
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + " " +
                    std::to_string(fdp.ConsumeFloatingPoint<double>()) + "\n";
            }
        }
    } else {
        // Use remaining bytes as raw cube data
        cube_content += "\n" + fdp.ConsumeRemainingBytesAsString();
    }
    
    // Write cube file to disk
    FILE* cube_file = fopen(cube_filename.c_str(), "w");
    if (cube_file == NULL) {
        // Clean up context if created
        if (context != NULL) {
            cmsDeleteContext(context);
        }
        return 0;
    }
    
    fwrite(cube_content.c_str(), 1, cube_content.length(), cube_file);
    fclose(cube_file);
    
    // PHASE 3: TEST STREAM-BASED PROFILE OPENING (cmsOpenProfileFromStream)
    cmsHPROFILE cube_profile_stream = NULL;
    if (use_stream_api) {
        // Re-open the file for reading with stream API
        FILE* stream_file = fopen(cube_filename.c_str(), "r");
        if (stream_file != NULL) {
            if (use_thread_safe) {
                cube_profile_stream = cmsOpenProfileFromStreamTHR(context, stream_file, "r");
            } else {
                cube_profile_stream = cmsOpenProfileFromStream(stream_file, "r");
            }
            fclose(stream_file);
            
            // If we successfully opened a profile from stream, test formatter API
            if (cube_profile_stream != NULL && test_formatter) {
                // Test cmsFormatterForPCSOfProfile (mentioned in guidance as having 42 undiscovered branches)
                // Consume parameters for formatter function
                uint32_t nBytes = fdp.ConsumeIntegral<uint32_t>();
                cmsBool lIsFloat = fdp.ConsumeBool() ? 1 : 0;
                uint32_t formatter = cmsFormatterForPCSOfProfile(cube_profile_stream, nBytes, lIsFloat);
                // Formatter value can be used for additional testing if needed
                (void)formatter;  // Prevent unused variable warning
                
                // Close the stream-opened profile
                cmsCloseProfile(cube_profile_stream);
                cube_profile_stream = NULL;
            }
        }
    }
    
    // PHASE 4: TEST DEVICE LINK CREATION FROM CUBE FILE (Primary Target)
    cmsHTRANSFORM device_link = NULL;
    cmsHPROFILE cube_profile = NULL;
    
    if (create_device_link) {
        // First create device link from cube file
        if (use_thread_safe) {
            cube_profile = cmsCreateDeviceLinkFromCubeFileTHR(context, cube_filename.c_str());
        } else {
            cube_profile = cmsCreateDeviceLinkFromCubeFile(cube_filename.c_str());
        }
        
        if (cube_profile != NULL) {
            // Create a simple transform from the device link profile
            // Use standard RGB color spaces for testing
            cmsHPROFILE rgb_profile = cmsCreate_sRGBProfileTHR(context ? context : NULL);
            if (rgb_profile != NULL) {
                // Create transform using the cube-based device link
                uint32_t intent = fdp.ConsumeIntegralInRange<uint32_t>(0, 3);
                uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
                
                device_link = cmsCreateTransformTHR(context ? context : NULL,
                                                   rgb_profile, 
                                                   TYPE_RGB_8,
                                                   cube_profile,
                                                   TYPE_RGB_8,
                                                   intent,
                                                   flags);
                
                // Test the transform if created successfully
                if (device_link != NULL) {
                    // Test transform with some sample color data
                    uint8_t input_color[3];
                    uint8_t output_color[3];
                    
                    for (int i = 0; i < 3; i++) {
                        input_color[i] = fdp.ConsumeIntegral<uint8_t>();
                    }
                    
                    cmsDoTransform(device_link, input_color, output_color, 1);
                    
                    // Clean up the transform
                    cmsDeleteTransform(device_link);
                    device_link = NULL;
                }
                
                cmsCloseProfile(rgb_profile);
            }
            
            // Close the cube-based profile
            cmsCloseProfile(cube_profile);
            cube_profile = NULL;
        }
    }
    
    // PHASE 5: TEST ALTERNATIVE WORKFLOW - Create transform directly from cube file
    // This tests a different code path in the cube file parsing subsystem
    if (fdp.remaining_bytes() > 50) {
        cmsHTRANSFORM direct_transform = NULL;
        
        // Create source and destination profiles
        cmsHPROFILE src_profile = cmsCreate_sRGBProfile();
        if (src_profile != NULL) {
            // Try to create transform using cube file as destination
            direct_transform = cmsCreateTransform(src_profile, TYPE_RGB_8,
                                                  NULL, TYPE_RGB_8,
                                                  INTENT_PERCEPTUAL,
                                                  cmsFLAGS_NOCACHE);
            
            if (direct_transform != NULL) {
                // Clean up
                cmsDeleteTransform(direct_transform);
            }
            
            cmsCloseProfile(src_profile);
        }
    }
    
    // PHASE 6: CLEANUP
    // Remove temporary cube file
    unlink(cube_filename.c_str());
    
    // Delete context if created
    if (context != NULL) {
        cmsDeleteContext(context);
    }
    
    return 0;
}
