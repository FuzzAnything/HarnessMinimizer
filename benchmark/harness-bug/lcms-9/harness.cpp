// Fuzzing harness for Little CMS 2 library
// Target: Profile I/O operations, MD5 computation, and plugin management with 700+ undiscovered branches
// Strategy: Follow the exact workflow from coverage guidance:
//           1. Create a test profile using cmsCreateRGBProfile (already covered helper)
//           2. Save profile to temporary file and memory buffer for subsequent tests
//           3. Test all profile opening variants:
//              - cmsOpenProfileFromFile/THR (file-based)
//              - cmsOpenProfileFromStream/THR (stream-based)
//              - cmsOpenProfileFromIOhandlerTHR/2THR (IOhandler-based)
//           4. Compute MD5 ID for profiles using cmsMD5computeID
//           5. Test plugin management with cmsPlugin
//           6. Save profiles to memory and streams using cmsSaveProfileToMem and cmsSaveProfileToStream
//           7. Clean up: cmsCloseProfile, cmsCloseIOhandler, cmsDeleteContext
// Focus APIs: cmsOpenProfileFromStream (88 undiscovered branches),
//             cmsOpenProfileFromStreamTHR (88), cmsOpenProfileFromFile (86),
//             cmsOpenProfileFromFileTHR (86), cmsOpenProfileFromIOhandler2THR (82),
//             cmsOpenProfileFromIOhandlerTHR (80), cmsSaveProfileToMem (51),
//             cmsSaveProfileToStream (40), cmsMD5computeID (77), cmsPlugin (56)
// Helper APIs: cmsOpenIOhandlerFromStream, cmsCloseIOhandler, cmsCloseProfile
// Semantic uniqueness: First harness to comprehensively target all profile I/O operations,
//                      implements full workflow from profile creation to saving with MD5 and plugins,
//                      tests all opening variants (file, stream, IOhandler) for maximum coverage
// IMPORTANT: This harness correctly handles FILE* ownership semantics:
//   - cmsOpenProfileFromStream/THR: Library takes ownership of FILE* on success
//   - cmsOpenProfileFromIOhandlerTHR/2THR: Library takes ownership of IOhandler (which owns FILE*) on success
//   - cmsSaveProfileToStream: Library creates IOhandler and closes FILE* internally
//   - On failure: Harness retains ownership and must close resources

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for profile creation and operations
    // We need: white point (3 floats), primaries (9 floats), gamma value, filename, etc.
    if (size < 256) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create context for THR functions
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }
    
    // Step 2: Create a test profile for I/O operations
    // Use fuzzer input for profile parameters
    
    cmsCIExyY white_point;
    white_point.x = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    white_point.y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    white_point.Y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    
    cmsCIExyYTRIPLE primaries;
    primaries.Red.x = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Red.y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Red.Y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Green.x = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Green.y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Green.Y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Blue.x = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Blue.y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    primaries.Blue.Y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    
    // Create gamma curve with fuzzer-provided gamma value
    cmsFloat64Number gamma = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.5, 5.0);
    cmsToneCurve* gamma_curve = cmsBuildGamma(context, gamma);
    if (gamma_curve == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    
    cmsToneCurve* transfer_functions[3] = {gamma_curve, gamma_curve, gamma_curve};
    
    // Create RGB profile for testing
    cmsHPROFILE test_profile = cmsCreateRGBProfile(&white_point, &primaries, transfer_functions);
    if (test_profile == NULL) {
        cmsFreeToneCurve(gamma_curve);
        cmsDeleteContext(context);
        return 0;
    }
    // Step 3: Save profile to temporary file for file-based opening tests
    // Create temporary filename from fuzzer input
    std::string temp_filename = "/tmp/lcms_test_";
    temp_filename += fdp.ConsumeRandomLengthString(16);
    temp_filename += ".icc";
    
    // Save profile to file
    cmsBool save_success = cmsSaveProfileToFile(test_profile, temp_filename.c_str());
    if (!save_success) {
        // Clean up and continue with other tests
        cmsCloseProfile(test_profile);
        cmsFreeToneCurve(gamma_curve);
        cmsDeleteContext(context);
        return 0;
    }
    
    // Step 4: Test file-based profile opening variants
    
    // 4.1: cmsOpenProfileFromFile (86 undiscovered branches)
    cmsHPROFILE file_profile1 = cmsOpenProfileFromFile(temp_filename.c_str(), "r");
    if (file_profile1 != NULL) {
        // Test MD5 computation on opened profile (77 undiscovered branches)
        cmsMD5computeID(file_profile1);
        cmsCloseProfile(file_profile1);
    }
    
    // 4.2: cmsOpenProfileFromFileTHR (86 undiscovered branches)
    cmsHPROFILE file_profile2 = cmsOpenProfileFromFileTHR(context, temp_filename.c_str(), "r");
    if (file_profile2 != NULL) {
        cmsMD5computeID(file_profile2);
        cmsCloseProfile(file_profile2);
    }
    
    // Step 5: Test stream-based profile opening variants
    // Open the saved file as a stream
    FILE* file_stream = fopen(temp_filename.c_str(), "rb");
    if (file_stream != NULL) {
        // 5.1: cmsOpenProfileFromStream (88 undiscovered branches)
        cmsHPROFILE stream_profile1 = cmsOpenProfileFromStream(file_stream, "r");
        if (stream_profile1 != NULL) {
            cmsMD5computeID(stream_profile1);
            cmsCloseProfile(stream_profile1);  // Library closes file_stream here
            
            // Library took ownership, so we need a new stream for next test
            file_stream = fopen(temp_filename.c_str(), "rb");
            if (file_stream != NULL) {
                // 5.2: cmsOpenProfileFromStreamTHR (88 undiscovered branches)
                cmsHPROFILE stream_profile2 = cmsOpenProfileFromStreamTHR(context, file_stream, "r");
                if (stream_profile2 != NULL) {
                    cmsMD5computeID(stream_profile2);
                    cmsCloseProfile(stream_profile2);  // Library closes file_stream here
                } else {
                    // If opening failed and we still own the FILE*, close it
                    fclose(file_stream);
                }
            }
        } else {
            // If opening failed, we still own the FILE* and need to close it
            fclose(file_stream);
        }
    }
    
    // Step 6: Test IOhandler-based profile opening variants
    // Reopen file stream for IOhandler tests
    file_stream = fopen(temp_filename.c_str(), "rb");
    if (file_stream != NULL) {
        // 6.1: Create IOhandler from stream
        cmsIOHANDLER* io_handler = cmsOpenIOhandlerFromStream(context, file_stream);
        if (io_handler != NULL) {
            // 6.2: cmsOpenProfileFromIOhandlerTHR (80 undiscovered branches)
            cmsHPROFILE iohandler_profile1 = cmsOpenProfileFromIOhandlerTHR(context, io_handler);
            if (iohandler_profile1 != NULL) {
                cmsMD5computeID(iohandler_profile1);
                cmsCloseProfile(iohandler_profile1);  // Library closes IOhandler which owns the FILE*
            } else {
                // If opening failed, we need to close the IOhandler (which will close the FILE*)
                cmsCloseIOhandler(io_handler);
            }
            
            // Note: If iohandler_profile1 succeeded, library took ownership of io_handler
            // If it failed, we already closed io_handler above
            // Either way, we need a new stream for the next test
            file_stream = fopen(temp_filename.c_str(), "rb");
            if (file_stream != NULL) {
                cmsIOHANDLER* io_handler2 = cmsOpenIOhandlerFromStream(context, file_stream);
                if (io_handler2 != NULL) {
                    // 6.3: cmsOpenProfileFromIOhandler2THR (82 undiscovered branches)
                    // Test both read and write modes based on fuzzer input
                    bool try_write = fdp.ConsumeBool();
                    cmsHPROFILE iohandler_profile2 = cmsOpenProfileFromIOhandler2THR(
                        context, io_handler2, try_write ? TRUE : FALSE);
                    
                    if (iohandler_profile2 != NULL) {
                        cmsMD5computeID(iohandler_profile2);
                        cmsCloseProfile(iohandler_profile2);  // Library closes IOhandler which owns the FILE*
                    } else {
                        // If opening failed, still need to close IOhandler (which will close the FILE*)
                        cmsCloseIOhandler(io_handler2);
                    }
                } else {
                    // Failed to create IOhandler, we own the FILE*
                    fclose(file_stream);
                }
            }
        } else {
            // Failed to create IOhandler, we own the FILE*
            fclose(file_stream);
        }
    }
    
    // Step 7: Test plugin management (56 undiscovered branches)
    // Create a simple plugin structure for testing
    // Note: Actual plugin structure would be more complex, but we can test the API
    // For fuzzing purposes, we'll pass NULL to test error paths
    cmsPlugin(NULL);
    cmsPluginTHR(context, NULL);
    
    // Step 8: Test profile saving variants
    
    // 8.1: cmsSaveProfileToMem (51 undiscovered branches)
    // First get size needed
    cmsUInt32Number mem_size = 0;
    cmsSaveProfileToMem(test_profile, NULL, &mem_size);
    
    if (mem_size > 0 && mem_size < 1024*1024) {  // Reasonable size limit
        std::vector<uint8_t> profile_buffer(mem_size);
        cmsSaveProfileToMem(test_profile, profile_buffer.data(), &mem_size);
        
        // Now try to open the profile from memory
        cmsHPROFILE mem_profile = cmsOpenProfileFromMem(profile_buffer.data(), mem_size);
        if (mem_profile != NULL) {
            cmsMD5computeID(mem_profile);
            cmsCloseProfile(mem_profile);
        }
    }
    
    // 8.2: cmsSaveProfileToStream (40 undiscovered branches)
    // Create a temporary file for stream saving
    std::string stream_filename = "/tmp/lcms_stream_";
    stream_filename += fdp.ConsumeRandomLengthString(16);
    stream_filename += ".icc";
    
    FILE* save_stream = fopen(stream_filename.c_str(), "wb");
    if (save_stream != NULL) {
        cmsSaveProfileToStream(test_profile, save_stream);  // Library creates IOhandler and closes save_stream
        
        // Try to open the saved stream file - need a new stream since library closed the previous one
        FILE* read_stream = fopen(stream_filename.c_str(), "rb");
        if (read_stream != NULL) {
            cmsHPROFILE saved_profile = cmsOpenProfileFromStream(read_stream, "r");
            if (saved_profile != NULL) {
                cmsMD5computeID(saved_profile);
                cmsCloseProfile(saved_profile);  // Library closes read_stream
            } else {
                // Opening failed, we own the FILE*
                fclose(read_stream);
            }
        }
        
        // Clean up temp file
        remove(stream_filename.c_str());
    }
    
    // Step 9: Test profile saving with write access modes
    // Create a new profile with write access
    FILE* write_stream = fopen(temp_filename.c_str(), "r+b");
    if (write_stream != NULL) {
        cmsHPROFILE write_profile = cmsOpenProfileFromStream(write_stream, "w");
        if (write_profile != NULL) {
            // Could modify and save here, but for simplicity just close
            cmsCloseProfile(write_profile);  // Library closes write_stream
        } else {
            // Opening failed, we own the FILE*
            fclose(write_stream);
        }
    }
    
    // Step 10: Clean up
    
    // Remove temporary file
    remove(temp_filename.c_str());
    
    // Free resources
    cmsCloseProfile(test_profile);
    cmsFreeToneCurve(gamma_curve);
    cmsDeleteContext(context);
    
    return 0;
}
